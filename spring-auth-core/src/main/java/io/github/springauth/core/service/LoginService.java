package io.github.springauth.core.service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.security.SecureRandom;

import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.error.AuthException;
import io.github.springauth.core.error.InvalidCredentialsException;
import io.github.springauth.core.jwt.JwtIssuer;
import io.github.springauth.core.jwt.TokenPurpose;
import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserStatus;
import io.github.springauth.core.model.Credentials;
import io.github.springauth.core.model.LockoutPolicy;
import io.github.springauth.core.model.LoginFailureReason;
import io.github.springauth.core.model.MfaCredential;
import io.github.springauth.core.model.MfaStatus;
import io.github.springauth.core.model.RequestContext;
import io.github.springauth.core.port.CredentialsStore;
import io.github.springauth.core.port.MfaCredentialStore;
import io.github.springauth.core.spi.AuthMessenger;
import io.github.springauth.core.spi.AuthUserDirectory;
import io.github.springauth.core.spi.LoginGuard;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

/**
 * The password step of authentication.
 *
 * <p>Depending on the account it either completes the login, or hands back a short-lived token
 * pointing at the MFA step. See {@link LoginResult.Status}.
 *
 * <h2>Why every failure looks the same</h2>
 * <p>Unknown login, wrong password, disabled account, unactivated invitation and locked account
 * all produce the same {@link InvalidCredentialsException}. Anything more specific is an account
 * enumeration oracle: an attacker learns which addresses are registered without ever guessing a
 * password. The real reason goes to the login history.
 *
 * <p>The same reasoning covers timing. A missing account would otherwise answer in a millisecond
 * while a real one spends ~250 ms in BCrypt, and that difference alone is a reliable oracle. Every
 * early exit therefore runs one throwaway hash comparison first.
 *
 * <h2>Transaction semantics</h2>
 * <p>{@code noRollbackFor = AuthException.class} is not a detail: a wrong password increments the
 * failure counter and then throws, and a rollback would erase the increment. Lock-out would then
 * never trigger, no matter how many attempts an attacker made.
 */
@Transactional(noRollbackFor = AuthException.class)
public class LoginService {

    private static final Logger log = LoggerFactory.getLogger(LoginService.class);

    private final AuthUserDirectory userDirectory;
    private final CredentialsStore credentialsStore;
    private final MfaCredentialStore mfaCredentialStore;
    private final PasswordEncoder passwordEncoder;
    private final JwtIssuer jwtIssuer;
    private final SessionService sessionService;
    private final AuthAuditor auditor;
    private final LoginGuard loginGuard;
    private final AuthMessenger messenger;
    private final AuthProperties properties;
    private final Clock clock;

    /**
     * Hash of a random value, computed once at startup with the configured cost so that its
     * verification takes exactly as long as a real one.
     */
    private final String timingEqualisationHash;

    public LoginService(AuthUserDirectory userDirectory,
                        CredentialsStore credentialsStore,
                        MfaCredentialStore mfaCredentialStore,
                        PasswordEncoder passwordEncoder,
                        JwtIssuer jwtIssuer,
                        SessionService sessionService,
                        AuthAuditor auditor,
                        LoginGuard loginGuard,
                        AuthMessenger messenger,
                        AuthProperties properties,
                        Clock clock) {
        this.userDirectory = userDirectory;
        this.credentialsStore = credentialsStore;
        this.mfaCredentialStore = mfaCredentialStore;
        this.passwordEncoder = passwordEncoder;
        this.jwtIssuer = jwtIssuer;
        this.sessionService = sessionService;
        this.auditor = auditor;
        this.loginGuard = loginGuard;
        this.messenger = messenger;
        this.properties = properties;
        this.clock = clock;
        this.timingEqualisationHash = passwordEncoder.encode(randomSecret());
    }

    /**
     * Authenticates a login and password.
     *
     * @throws InvalidCredentialsException on any authentication failure, whatever its cause
     * @throws AuthException               when a {@link LoginGuard} vetoes the attempt
     */
    public LoginResult login(String login, String rawPassword, RequestContext context) {
        Instant now = clock.instant();
        String submittedLogin = login == null ? "" : login.trim();

        Optional<AuthUser> found = userDirectory.findByLogin(submittedLogin);
        if (found.isEmpty()) {
            equaliseTiming(rawPassword);
            auditor.loginFailed(null, submittedLogin, LoginFailureReason.UNKNOWN_LOGIN, context, now);
            throw new InvalidCredentialsException();
        }
        AuthUser user = found.get();

        if (!user.canAuthenticate()) {
            equaliseTiming(rawPassword);
            auditor.loginFailed(user.id(), submittedLogin, reasonFor(user.status()), context, now);
            throw new InvalidCredentialsException();
        }

        Optional<Credentials> stored = credentialsStore.findByUserId(user.id());
        if (stored.isEmpty()) {
            equaliseTiming(rawPassword);
            log.warn("spring-auth: no credentials stored for userId={}", user.id().value());
            auditor.loginFailed(user.id(), submittedLogin, LoginFailureReason.NO_PASSWORD, context, now);
            throw new InvalidCredentialsException();
        }
        Credentials credentials = stored.get();

        if (credentials.isLockedAt(now)) {
            equaliseTiming(rawPassword);
            auditor.loginFailed(user.id(), submittedLogin, LoginFailureReason.LOCKED, context, now);
            throw new InvalidCredentialsException();
        }

        if (!passwordEncoder.matches(rawPassword, credentials.getPasswordHash())) {
            boolean justLocked = credentials.recordFailedAttempt(lockoutPolicy(), now);
            credentialsStore.save(credentials);
            if (justLocked) {
                notifyAccountLocked(user, credentials.getLockedUntil(), context);
            }
            auditor.loginFailed(user.id(), submittedLogin, LoginFailureReason.BAD_PASSWORD, context, now);
            throw new InvalidCredentialsException();
        }

        // The password is proven at this point, so an application rule may now speak up with a
        // specific message. Nothing has been issued and nothing has been persisted yet.
        loginGuard.check(user, context);

        credentials.recordSuccessfulAuthentication(now);
        credentialsStore.save(credentials);
        auditor.loginSucceeded(user, context, now);

        boolean mustChangePassword = credentials.requiresPasswordChange(
                now, properties.getPassword().getMaxAge());

        if (!user.requiresMfa()) {
            return LoginResult.authenticated(user.id(), user.login(), MfaStatus.NOT_APPLICABLE,
                    mustChangePassword, sessionService.openSession(user));
        }
        return continueWithMfa(user, mustChangePassword);
    }

    /**
     * Recomputes what a user must do about MFA, without touching their password.
     * Used by the enrolment endpoints to re-derive state from a purpose token.
     */
    @Transactional(readOnly = true)
    public MfaStatus mfaStatusOf(AuthUser user) {
        if (!user.requiresMfa()) {
            return MfaStatus.NOT_APPLICABLE;
        }
        return mfaCredentialStore.findByUserId(user.id())
                .map(MfaCredential::status)
                .orElse(MfaStatus.NOT_CONFIGURED);
    }

    private LoginResult continueWithMfa(AuthUser user, boolean mustChangePassword) {
        MfaStatus status = mfaStatusOf(user);
        if (status == MfaStatus.CONFIGURED) {
            JwtIssuer.IssuedToken challenge = jwtIssuer.issuePurposeToken(
                    user.id(), TokenPurpose.MFA_CHALLENGE, properties.getMfa().getChallengeTtl());
            return LoginResult.mfaChallengeRequired(user.id(), user.login(),
                    mustChangePassword, challenge.token());
        }
        JwtIssuer.IssuedToken enrollment = jwtIssuer.issuePurposeToken(
                user.id(), TokenPurpose.MFA_ENROLLMENT, properties.getMfa().getEnrollmentTtl());
        return LoginResult.mfaEnrollmentRequired(user.id(), user.login(), status,
                mustChangePassword, enrollment.token());
    }

    private void notifyAccountLocked(AuthUser user, Instant lockedUntil, RequestContext context) {
        auditor.accountLocked(user, lockedUntil, context);
        try {
            messenger.sendAccountLockedAlert(user, lockedUntil);
        } catch (RuntimeException ex) {
            log.warn("spring-auth: account-locked alert could not be sent for userId={}",
                    user.id().value(), ex);
        }
    }

    private LockoutPolicy lockoutPolicy() {
        AuthProperties.Password password = properties.getPassword();
        return new LockoutPolicy(password.getMaxFailedAttempts(), password.getLockoutDuration());
    }

    private static LoginFailureReason reasonFor(AuthUserStatus status) {
        return switch (status) {
            case PENDING_ACTIVATION -> LoginFailureReason.NOT_ACTIVATED;
            case DISABLED, ARCHIVED -> LoginFailureReason.DISABLED;
            case ACTIVE -> LoginFailureReason.REJECTED_BY_APPLICATION;
        };
    }

    /**
     * Burns the same amount of CPU a real password check would, so that "no such account" and
     * "wrong password" are indistinguishable from the outside.
     */
    private void equaliseTiming(String rawPassword) {
        passwordEncoder.matches(rawPassword == null ? "" : rawPassword, timingEqualisationHash);
    }

    private static String randomSecret() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    /** Exposed for the diagnostics endpoint: how long a lock lasts once triggered. */
    public Duration getLockoutDuration() {
        return properties.getPassword().getLockoutDuration();
    }
}
