package io.github.springauth.core.testsupport;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.crypto.NumericOtpFactory;
import io.github.springauth.core.crypto.OpaqueTokenFactory;
import io.github.springauth.core.crypto.SecretCipher;
import io.github.springauth.core.crypto.TotpGenerator;
import io.github.springauth.core.jwt.JwtIssuer;
import io.github.springauth.core.jwt.JwtKeyProvider;
import io.github.springauth.core.jwt.PurposeTokenVerifier;
import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.service.AuthAuditor;
import io.github.springauth.core.service.InvitationService;
import io.github.springauth.core.service.LoginService;
import io.github.springauth.core.service.MfaService;
import io.github.springauth.core.service.PasswordPolicy;
import io.github.springauth.core.service.PasswordService;
import io.github.springauth.core.service.PermissionResolver;
import io.github.springauth.core.service.SessionService;
import io.github.springauth.core.spi.AuthMessenger;
import io.github.springauth.core.spi.LoginGuard;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Assembles the whole service graph over in-memory stores, on a controllable clock.
 *
 * <p>BCrypt runs at cost 4 here. That is far too weak for production and exactly right for tests:
 * the production cost of 12 would add roughly a quarter of a second to every password operation,
 * and these tests perform many.
 */
public class AuthTestFixture {

    public static final Instant START = Instant.parse("2026-03-01T10:00:00Z");

    public final AuthProperties properties = new AuthProperties();
    public final MutableClock clock = new MutableClock(START);
    public final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(4);

    public final FakeUserDirectory directory = new FakeUserDirectory();
    public final InMemoryStores.Credentials credentials = new InMemoryStores.Credentials();
    public final InMemoryStores.PasswordHistory passwordHistory = new InMemoryStores.PasswordHistory();
    public final InMemoryStores.MfaCredentials mfaCredentials = new InMemoryStores.MfaCredentials();
    public final InMemoryStores.RefreshTokens refreshTokens = new InMemoryStores.RefreshTokens();
    public final InMemoryStores.PasswordResets passwordResets = new InMemoryStores.PasswordResets();
    public final InMemoryStores.Invitations invitations = new InMemoryStores.Invitations();
    public final InMemoryStores.LoginHistory loginHistory = new InMemoryStores.LoginHistory();
    public final InMemoryStores.Roles roles = new InMemoryStores.Roles();

    public final RecordingMessenger messenger = new RecordingMessenger();
    public final RecordingEventListener events = new RecordingEventListener();
    public final InMemoryRevocationStore revocations = new InMemoryRevocationStore();

    public final TotpGenerator totpGenerator = new TotpGenerator();
    public final SecretCipher secretCipher = new SecretCipher(SecretCipher.generateMasterKey());
    public final OpaqueTokenFactory tokenFactory = new OpaqueTokenFactory();

    public final JwtKeyProvider keyProvider;
    public final JwtIssuer jwtIssuer;
    public final PurposeTokenVerifier purposeTokenVerifier;
    public final SessionService sessionService;
    public final LoginService loginService;
    public final MfaService mfaService;
    public final PasswordService passwordService;
    public final InvitationService invitationService;

    private LoginGuard loginGuard = LoginGuard.permitAll();

    public AuthTestFixture() {
        this(new AuthProperties());
    }

    public AuthTestFixture(AuthProperties overrides) {
        copy(overrides);
        properties.getPassword().setBcryptCost(4);

        this.keyProvider = new JwtKeyProvider("", "", "test-key", "", "", false);
        this.jwtIssuer = new JwtIssuer(keyProvider, properties.getJwt(), clock);
        this.purposeTokenVerifier = new PurposeTokenVerifier(keyProvider, properties.getJwt(), clock);

        AuthAuditor auditor = new AuthAuditor(loginHistory, List.of(events));
        PermissionResolver permissionResolver = new PermissionResolver(roles);
        PasswordPolicy passwordPolicy = new PasswordPolicy(properties.getPassword());
        NumericOtpFactory otpFactory = new NumericOtpFactory(passwordEncoder,
                properties.getPasswordReset().getOtpDigits());

        this.sessionService = new SessionService(refreshTokens, credentials, revocations, directory,
                tokenFactory, jwtIssuer, permissionResolver, auditor, properties, clock);
        this.mfaService = new MfaService(mfaCredentials, directory, purposeTokenVerifier, totpGenerator,
                secretCipher, sessionService, auditor, properties, clock);
        this.passwordService = new PasswordService(credentials, passwordHistory, passwordResets,
                directory, passwordEncoder, passwordPolicy, tokenFactory, otpFactory, sessionService,
                messenger, auditor, properties, clock);
        this.invitationService = new InvitationService(invitations, directory, tokenFactory,
                passwordService, messenger, auditor, properties, clock);
        this.loginService = new LoginService(directory, credentials, mfaCredentials, passwordEncoder,
                jwtIssuer, sessionService, auditor, (user, context) -> loginGuard.check(user, context),
                messenger, properties, clock);
    }

    /**
     * Registers a user and its password in one call.
     *
     * <p>The hash also lands in the history, exactly as {@code PasswordService.initialise} would:
     * the very first password counts towards the no-reuse rule.
     */
    public AuthTestFixture withUser(AuthUser user, String rawPassword) {
        directory.add(user);
        String hash = passwordEncoder.encode(rawPassword);
        credentials.save(io.github.springauth.core.model.Credentials.create(
                user.id(), hash, false, clock.instant()));
        passwordHistory.append(user.id(), hash, clock.instant());
        return this;
    }

    /** Installs an application veto to exercise the {@link LoginGuard} seam. */
    public AuthTestFixture withLoginGuard(LoginGuard guard) {
        this.loginGuard = guard;
        return this;
    }

    /** Current valid TOTP code for a user whose factor is enrolled. */
    public String currentTotpCode(AuthUser user) {
        String secret = secretCipher.decrypt(
                mfaCredentials.findByUserId(user.id()).orElseThrow().getEncryptedSecret());
        return totpGenerator.codeAt(secret, clock.instant(), properties.getMfa().getDigits());
    }

    private void copy(AuthProperties source) {
        // AuthProperties exposes nested mutable holders, so the caller configures the instance it
        // passes in and the fixture keeps using that same graph.
        if (source != properties) {
            properties.getJwt().setAccessTtl(source.getJwt().getAccessTtl());
            properties.getPassword().setMinLength(source.getPassword().getMinLength());
            properties.getPassword().setHistorySize(source.getPassword().getHistorySize());
            properties.getPassword().setMaxFailedAttempts(source.getPassword().getMaxFailedAttempts());
            properties.getPasswordReset().setRequireOtp(source.getPasswordReset().isRequireOtp());
        }
    }

    /** Clock the tests move forward by hand. */
    public static class MutableClock extends Clock {

        private Instant now;

        public MutableClock(Instant start) {
            this.now = start;
        }

        public void advance(java.time.Duration amount) {
            this.now = now.plus(amount);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /** Captures what would have been delivered to the user. */
    public static class RecordingMessenger implements AuthMessenger {

        public final List<String> passwordResetTokens = new ArrayList<>();
        public final List<String> passwordResetOtps = new ArrayList<>();
        public final List<String> invitationTokens = new ArrayList<>();
        public int accountLockedAlerts;
        public int passwordChangedNotices;

        @Override
        public void sendPasswordResetOtp(AuthUser user, String rawToken, String rawOtp, Instant expiresAt) {
            passwordResetTokens.add(rawToken);
            if (rawOtp != null) {
                passwordResetOtps.add(rawOtp);
            }
        }

        @Override
        public void sendInvitation(AuthUser user, String rawToken, Instant expiresAt) {
            invitationTokens.add(rawToken);
        }

        @Override
        public void sendAccountLockedAlert(AuthUser user, Instant lockedUntil) {
            accountLockedAlerts++;
        }

        @Override
        public void sendPasswordChangedNotice(AuthUser user, Instant changedAt) {
            passwordChangedNotices++;
        }
    }
}
