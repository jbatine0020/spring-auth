package io.github.springauth.core.service;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.crypto.NumericOtpFactory;
import io.github.springauth.core.crypto.OpaqueTokenFactory;
import io.github.springauth.core.error.PasswordException;
import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.Credentials;
import io.github.springauth.core.model.PasswordResetRequest;
import io.github.springauth.core.model.RequestContext;
import io.github.springauth.core.port.CredentialsStore;
import io.github.springauth.core.port.PasswordHistoryStore;
import io.github.springauth.core.port.PasswordResetStore;
import io.github.springauth.core.spi.AuthMessenger;
import io.github.springauth.core.spi.AuthUserDirectory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

/**
 * Everything that sets or changes a password: self-service change, administrative reset, and the
 * forgotten-password flow.
 *
 * <h2>The forgotten-password flow</h2>
 * <p>{@link #requestReset} answers the same way whether or not the address is registered, because
 * a differentiated answer is a free account-existence oracle on an unauthenticated endpoint. The
 * link goes out by email and, when configured, a numeric code goes out by SMS: the two together
 * mean neither a compromised mailbox nor a stolen phone is enough on its own.
 *
 * <h2>Sessions are always closed</h2>
 * <p>Any password change revokes every session. This is the point of changing a password after a
 * suspected compromise: leaving the attacker's refresh token alive would defeat it.
 */
@Transactional
public class PasswordService {

    private static final Logger log = LoggerFactory.getLogger(PasswordService.class);

    private final CredentialsStore credentialsStore;
    private final PasswordHistoryStore passwordHistoryStore;
    private final PasswordResetStore passwordResetStore;
    private final AuthUserDirectory userDirectory;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final OpaqueTokenFactory tokenFactory;
    private final NumericOtpFactory otpFactory;
    private final SessionService sessionService;
    private final AuthMessenger messenger;
    private final AuthAuditor auditor;
    private final AuthProperties properties;
    private final Clock clock;

    public PasswordService(CredentialsStore credentialsStore,
                           PasswordHistoryStore passwordHistoryStore,
                           PasswordResetStore passwordResetStore,
                           AuthUserDirectory userDirectory,
                           PasswordEncoder passwordEncoder,
                           PasswordPolicy passwordPolicy,
                           OpaqueTokenFactory tokenFactory,
                           NumericOtpFactory otpFactory,
                           SessionService sessionService,
                           AuthMessenger messenger,
                           AuthAuditor auditor,
                           AuthProperties properties,
                           Clock clock) {
        this.credentialsStore = credentialsStore;
        this.passwordHistoryStore = passwordHistoryStore;
        this.passwordResetStore = passwordResetStore;
        this.userDirectory = userDirectory;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.tokenFactory = tokenFactory;
        this.otpFactory = otpFactory;
        this.sessionService = sessionService;
        this.messenger = messenger;
        this.auditor = auditor;
        this.properties = properties;
        this.clock = clock;
    }

    /**
     * Creates the first credentials of a user. Idempotent per user: an existing record is updated
     * rather than duplicated.
     *
     * @param mustChangeAtNextLogin true when the value is temporary
     */
    public void initialise(AuthUserId userId, String rawPassword, boolean mustChangeAtNextLogin) {
        passwordPolicy.validate(rawPassword);
        Instant now = clock.instant();
        String hash = passwordEncoder.encode(rawPassword);
        Credentials credentials = credentialsStore.findByUserId(userId)
                .map(existing -> {
                    existing.resetByAdministrator(hash, now);
                    return existing;
                })
                .orElseGet(() -> Credentials.create(userId, hash, mustChangeAtNextLogin, now));
        credentialsStore.save(credentials);
        passwordHistoryStore.append(userId, hash, now);
    }

    /**
     * Self-service change. Requires the current password, applies the policy and the no-reuse
     * rule, then closes every session so the user re-authenticates with the new secret.
     *
     * @throws PasswordException {@code PASSWORD_MISMATCH}, {@code PASSWORD_TOO_SHORT},
     *                           {@code PASSWORD_TOO_WEAK} or {@code PASSWORD_REUSED}
     */
    public void changeOwnPassword(AuthUserId userId, String currentPassword, String newPassword) {
        Instant now = clock.instant();
        Credentials credentials = credentialsStore.findByUserId(userId)
                .orElseThrow(PasswordException::currentPasswordMismatch);

        if (!passwordEncoder.matches(currentPassword, credentials.getPasswordHash())) {
            throw PasswordException.currentPasswordMismatch();
        }
        applyOwnPasswordChange(userId, credentials, newPassword, now);
    }

    /** Completes a required change for a caller already authenticated with a temporary password. */
    public void completeRequiredPasswordChange(AuthUserId userId, String newPassword) {
        Instant now = clock.instant();
        Credentials credentials = credentialsStore.findByUserId(userId)
                .orElseThrow(PasswordException::currentPasswordMismatch);
        if (!credentials.requiresPasswordChange(now, properties.getPassword().getMaxAge())) {
            throw PasswordException.changeNotRequired();
        }
        applyOwnPasswordChange(userId, credentials, newPassword, now);
    }

    private void applyOwnPasswordChange(AuthUserId userId, Credentials credentials,
                                       String newPassword, Instant now) {
        passwordPolicy.validate(newPassword);
        assertNotReused(userId, newPassword);

        String hash = passwordEncoder.encode(newPassword);
        credentials.changePassword(hash, now);
        credentialsStore.save(credentials);
        passwordHistoryStore.append(userId, hash, now);
        sessionService.revokeAllSessions(userId);

        userDirectory.findById(userId).ifPresent(user -> {
            auditor.passwordChanged(user, true, now);
            safely(() -> messenger.sendPasswordChangedNotice(user, now));
        });
    }

    /**
     * Administrative set: no current password required, and the user is forced to change it at
     * their next login.
     */
    public void setPassword(AuthUserId userId, String newPassword, boolean mustChangeAtNextLogin) {
        Instant now = clock.instant();
        passwordPolicy.validate(newPassword);
        String hash = passwordEncoder.encode(newPassword);

        Credentials credentials = credentialsStore.findByUserId(userId)
                .map(existing -> {
                    if (mustChangeAtNextLogin) {
                        existing.resetByAdministrator(hash, now);
                    } else {
                        existing.changePassword(hash, now);
                    }
                    return existing;
                })
                .orElseGet(() -> Credentials.create(userId, hash, mustChangeAtNextLogin, now));
        credentialsStore.save(credentials);
        passwordHistoryStore.append(userId, hash, now);
        sessionService.revokeAllSessions(userId);

        userDirectory.findById(userId).ifPresent(user -> auditor.passwordChanged(user, false, now));
    }

    /**
     * Starts a forgotten-password flow.
     *
     * <p>Always returns normally, including for an unknown address: the caller cannot tell
     * registered addresses from unregistered ones. When the account exists, any earlier pending
     * request is dropped so a user asking twice ends up with exactly one working link.
     */
    public void requestReset(String login, RequestContext context) {
        Instant now = clock.instant();
        Optional<AuthUser> found = userDirectory.findByLogin(login == null ? "" : login.trim());
        if (found.isEmpty()) {
            log.debug("spring-auth: password reset requested for an unknown login");
            return;
        }
        AuthUser user = found.get();
        if (!user.canAuthenticate()) {
            log.debug("spring-auth: password reset requested for a non-active account");
            return;
        }

        passwordResetStore.deleteByUserId(user.id());

        AuthProperties.PasswordReset config = properties.getPasswordReset();
        String rawToken = tokenFactory.generateRawToken();
        NumericOtpFactory.IssuedOtp otp = config.isRequireOtp() ? otpFactory.issue() : null;
        Instant expiresAt = now.plus(config.getLinkTtl());

        passwordResetStore.save(PasswordResetRequest.issue(
                user.id(), tokenFactory.hash(rawToken),
                otp == null ? null : otp.hash(), now, expiresAt, user.id().value()));

        auditor.passwordResetRequested(user, context, now);
        // Delivery is the application's job: the library has neither a mailer nor an SMS gateway.
        safely(() -> messenger.sendPasswordResetOtp(
                user, rawToken, otp == null ? null : otp.rawCode(), expiresAt));
    }

    /**
     * Completes a forgotten-password flow.
     *
     * @param rawToken   token from the emailed link
     * @param rawOtp     numeric code from the SMS, ignored when the deployment is link-only
     * @throws PasswordException when the link is unknown, expired, used, locked, when the code is
     *                           wrong, or when the new password breaks the policy
     */
    public void confirmReset(String rawToken, String rawOtp, String newPassword) {
        Instant now = clock.instant();
        if (rawToken == null || rawToken.isBlank()) {
            throw PasswordException.resetInvalid();
        }
        PasswordResetRequest request = passwordResetStore.findByTokenHash(tokenFactory.hash(rawToken))
                .orElseThrow(PasswordException::resetInvalid);

        if (request.isUsed()) {
            throw PasswordException.resetAlreadyUsed();
        }
        if (request.isLocked()) {
            throw PasswordException.resetLocked();
        }
        if (request.isExpiredAt(now)) {
            throw PasswordException.resetExpired();
        }

        if (request.requiresOtp() && !otpFactory.matches(rawOtp, request.getOtpHash())) {
            // Counted and persisted before throwing, otherwise the six-digit code would be
            // brute-forceable for the whole life of the link.
            request.recordFailedAttempt(properties.getPasswordReset().getMaxAttempts(), now);
            passwordResetStore.save(request);
            throw PasswordException.resetInvalid();
        }

        // Validate the new password before consuming the link, so a rejected password does not
        // cost the user their only reset attempt.
        passwordPolicy.validate(newPassword);
        assertNotReused(request.getUserId(), newPassword);

        request.consume(now);
        passwordResetStore.save(request);

        String hash = passwordEncoder.encode(newPassword);
        Credentials credentials = credentialsStore.findByUserId(request.getUserId())
                .map(existing -> {
                    existing.changePassword(hash, now);
                    return existing;
                })
                .orElseGet(() -> Credentials.create(request.getUserId(), hash, false, now));
        credentialsStore.save(credentials);
        passwordHistoryStore.append(request.getUserId(), hash, now);
        sessionService.revokeAllSessions(request.getUserId());
        passwordResetStore.deleteByUserId(request.getUserId());

        userDirectory.findById(request.getUserId()).ifPresent(user -> {
            auditor.passwordChanged(user, true, now);
            safely(() -> messenger.sendPasswordChangedNotice(user, now));
        });
    }

    /** Administrative unlock of an account locked by repeated failures. */
    public void unlock(AuthUserId userId) {
        Instant now = clock.instant();
        credentialsStore.findByUserId(userId).ifPresent(credentials -> {
            credentials.unlock(now);
            credentialsStore.save(credentials);
        });
    }

    /** Human-readable policy summary, for a registration or change form. */
    @Transactional(readOnly = true)
    public String describePolicy() {
        return passwordPolicy.describe();
    }

    private void assertNotReused(AuthUserId userId, String rawNewPassword) {
        int historySize = properties.getPassword().getHistorySize();
        if (historySize <= 0) {
            return;
        }
        List<String> recentHashes = passwordHistoryStore.findRecentHashes(userId, historySize);
        boolean reused = recentHashes.stream()
                .anyMatch(hash -> passwordEncoder.matches(rawNewPassword, hash));
        if (reused) {
            throw PasswordException.reused(historySize);
        }
    }

    private void safely(Runnable action) {
        try {
            action.run();
        } catch (RuntimeException ex) {
            log.warn("spring-auth: notification delivery failed", ex);
        }
    }
}
