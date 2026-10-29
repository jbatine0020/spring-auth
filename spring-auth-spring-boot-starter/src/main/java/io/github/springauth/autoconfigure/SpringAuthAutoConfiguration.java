package io.github.springauth.autoconfigure;

import java.time.Clock;
import java.util.List;

import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.crypto.NumericOtpFactory;
import io.github.springauth.core.crypto.OpaqueTokenFactory;
import io.github.springauth.core.crypto.SecretCipher;
import io.github.springauth.core.crypto.TotpGenerator;
import io.github.springauth.core.internal.InternalTokenService;
import io.github.springauth.core.jwt.JwtIssuer;
import io.github.springauth.core.jwt.JwtKeyProvider;
import io.github.springauth.core.jwt.PurposeTokenVerifier;
import io.github.springauth.core.port.AccessTokenRevocationStore;
import io.github.springauth.core.port.CredentialsStore;
import io.github.springauth.core.port.InvitationStore;
import io.github.springauth.core.port.LoginHistoryStore;
import io.github.springauth.core.port.MfaCredentialStore;
import io.github.springauth.core.port.OtpChallengeStore;
import io.github.springauth.core.port.PasswordHistoryStore;
import io.github.springauth.core.port.PasswordResetStore;
import io.github.springauth.core.port.RateLimiter;
import io.github.springauth.core.port.RefreshTokenStore;
import io.github.springauth.core.port.ReplayGuard;
import io.github.springauth.core.port.RoleStore;
import io.github.springauth.core.service.AuthAuditor;
import io.github.springauth.core.service.InvitationService;
import io.github.springauth.core.service.LoginHistoryService;
import io.github.springauth.core.service.LoginService;
import io.github.springauth.core.service.MfaChallengeIssuer;
import io.github.springauth.core.service.MfaService;
import io.github.springauth.core.service.PasswordPolicy;
import io.github.springauth.core.service.PasswordService;
import io.github.springauth.core.service.PermissionResolver;
import io.github.springauth.core.service.RoleService;
import io.github.springauth.core.service.SessionService;
import io.github.springauth.core.spi.AuthEventListener;
import io.github.springauth.core.spi.AuthMessenger;
import io.github.springauth.core.spi.AuthUserDirectory;
import io.github.springauth.core.spi.LoginGuard;
import io.github.springauth.core.identity.ExternalAuthenticationService;
import io.github.springauth.core.identity.IdentityMirrorService;
import io.github.springauth.core.identity.IdentityProvider;
import io.github.springauth.core.support.InMemoryAccessTokenRevocationStore;
import io.github.springauth.core.support.InMemoryRateLimiter;
import io.github.springauth.core.support.InMemoryReplayGuard;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Wires the core: crypto, JWT, and the authentication services.
 *
 * <p>Everything is {@code @ConditionalOnMissingBean}, so any single piece can be replaced by
 * declaring your own bean of the same type: a different {@code PasswordEncoder}, a fixed
 * {@code Clock} in tests, an {@code AuthMessenger} that talks to your mail service.
 *
 * <p>The services only appear once the application provides an {@link AuthUserDirectory}. Without
 * it the library has no idea who its users are, and starting with half a security stack wired
 * would be worse than not starting it at all.
 */
@AutoConfiguration
@EnableConfigurationProperties(AuthProperties.class)
@ConditionalOnProperty(prefix = "spring-auth", name = "enabled", havingValue = "true", matchIfMissing = true)
public class SpringAuthAutoConfiguration {

    @Bean
    @ConditionalOnBean({IdentityProvider.class, IdentityMirrorService.class})
    @ConditionalOnMissingBean
    public ExternalAuthenticationService externalAuthenticationService(IdentityProvider provider,
                                                                        IdentityMirrorService mirrorService,
                                                                        io.github.springauth.core.identity.ApplicationUserStore users) {
        return new ExternalAuthenticationService(provider, mirrorService, users);
    }

    @Bean
    @ConditionalOnBean(ExternalAuthenticationService.class)
    @ConditionalOnMissingBean
    public io.github.springauth.core.service.ExternalLoginService externalLoginService(
            ExternalAuthenticationService authentication, MfaChallengeIssuer issuer,
            SessionService sessionService, io.github.springauth.core.identity.ApplicationUserStore users,
            io.github.springauth.core.port.MfaCredentialStore mfaCredentials,
            io.github.springauth.core.service.LoginOtpService loginOtpService) {
        return new io.github.springauth.core.service.ExternalLoginService(authentication, issuer, sessionService, users, mfaCredentials, loginOtpService);
    }

    @Bean
    @ConditionalOnMissingBean
    public MfaChallengeIssuer mfaChallengeIssuer(JwtIssuer jwtIssuer, AuthProperties properties) {
        return new MfaChallengeIssuer(jwtIssuer, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public io.github.springauth.core.service.LoginOtpService loginOtpService(
            OtpChallengeStore challenges, NumericOtpFactory otpFactory, JwtIssuer jwtIssuer,
            PurposeTokenVerifier purposeTokens, AuthMessenger messenger, AuthUserDirectory users,
            SessionService sessions, AuthProperties properties, Clock clock) {
        return new io.github.springauth.core.service.LoginOtpService(challenges, otpFactory, jwtIssuer,
                purposeTokens, messenger, users, sessions, properties, clock);
    }

    /** System clock. Override with a fixed one to make time-dependent tests deterministic. */
    @Bean
    @ConditionalOnMissingBean
    public Clock springAuthClock() {
        return Clock.systemUTC();
    }

    /**
     * BCrypt at the configured cost.
     *
     * <p>Cost 12 is roughly a quarter of a second per hash: slow enough to make an offline
     * dictionary attack expensive, fast enough to stay invisible on a login.
     */
    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder passwordEncoder(AuthProperties properties) {
        return new BCryptPasswordEncoder(properties.getPassword().getBcryptCost());
    }

    /**
     * Cipher protecting TOTP seeds at rest.
     *
     * <p>With no configured key an ephemeral one is generated so local development works out of the
     * box, at the cost of every enrolled factor becoming unreadable after a restart, hence the
     * warning. Setting {@code spring-auth.jwt.require-persistent-keys=true} turns that convenience
     * into a startup failure, which is what any deployed environment should do.
     */
    @Bean
    @ConditionalOnMissingBean
    public SecretCipher springAuthSecretCipher(AuthProperties properties) {
        String masterKey = properties.getCrypto().getMasterKey();
        if (masterKey != null && !masterKey.isBlank()) {
            return new SecretCipher(masterKey);
        }
        if (properties.getJwt().isRequirePersistentKeys()) {
            throw new IllegalStateException(
                    "spring-auth.crypto.master-key is mandatory when require-persistent-keys=true");
        }
        LoggerFactory.getLogger(SpringAuthAutoConfiguration.class).warn(
                "spring-auth: no crypto master key configured. An EPHEMERAL one was generated. "
                        + "Every enrolled MFA factor becomes unreadable on restart. Set "
                        + "spring-auth.crypto.master-key outside local development "
                        + "(generate one with SecretCipher.generateMasterKey()).");
        return new SecretCipher(SecretCipher.generateMasterKey());
    }

    @Bean
    @ConditionalOnMissingBean
    public TotpGenerator springAuthTotpGenerator() {
        return new TotpGenerator();
    }

    @Bean
    @ConditionalOnMissingBean
    public OpaqueTokenFactory springAuthOpaqueTokenFactory() {
        return new OpaqueTokenFactory();
    }

    @Bean
    @ConditionalOnMissingBean
    public NumericOtpFactory springAuthNumericOtpFactory(PasswordEncoder passwordEncoder,
                                                         AuthProperties properties) {
        return new NumericOtpFactory(passwordEncoder, properties.getPasswordReset().getOtpDigits());
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtKeyProvider springAuthJwtKeyProvider(AuthProperties properties) {
        AuthProperties.Jwt jwt = properties.getJwt();
        return new JwtKeyProvider(jwt.getPrivateKey(), jwt.getPublicKey(), jwt.getKeyId(),
                jwt.getPreviousPublicKey(), jwt.getPreviousKeyId(), jwt.isRequirePersistentKeys());
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtIssuer springAuthJwtIssuer(JwtKeyProvider keyProvider, AuthProperties properties,
                                         Clock clock) {
        return new JwtIssuer(keyProvider, properties.getJwt(), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    public PurposeTokenVerifier springAuthPurposeTokenVerifier(JwtKeyProvider keyProvider,
                                                               AuthProperties properties,
                                                               Clock clock) {
        return new PurposeTokenVerifier(keyProvider, properties.getJwt(), clock);
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordPolicy springAuthPasswordPolicy(AuthProperties properties) {
        return new PasswordPolicy(properties.getPassword());
    }

    // ---- Single-instance defaults -----------------------------------------------------------
    // Swapped for Redis-backed implementations by SpringAuthRedisAutoConfiguration when Spring
    // Data Redis is on the classpath. Behind several replicas the in-memory variants are not
    // enough, and each one logs why in its own javadoc.

    @Bean
    @ConditionalOnMissingBean
    public RateLimiter springAuthRateLimiter(Clock clock) {
        return new InMemoryRateLimiter(clock);
    }

    @Bean
    @ConditionalOnMissingBean
    public AccessTokenRevocationStore springAuthAccessTokenRevocationStore(Clock clock) {
        return new InMemoryAccessTokenRevocationStore(clock);
    }

    @Bean
    @ConditionalOnMissingBean
    public ReplayGuard springAuthReplayGuard(Clock clock) {
        return new InMemoryReplayGuard(clock);
    }

    // ---- SPI defaults -----------------------------------------------------------------------

    /** No-op messenger. Replace it: without one, reset codes and invitations go nowhere. */
    @Bean
    @ConditionalOnMissingBean
    public AuthMessenger springAuthMessenger() {
        return new NoOpAuthMessenger();
    }

    /** Accepts every authentication that already passed the password and MFA checks. */
    @Bean
    @ConditionalOnMissingBean
    public LoginGuard springAuthLoginGuard() {
        return LoginGuard.permitAll();
    }

    // ---- Services ---------------------------------------------------------------------------

    @Bean
    @ConditionalOnMissingBean
    public AuthAuditor springAuthAuditor(LoginHistoryStore loginHistoryStore,
                                         List<AuthEventListener> listeners) {
        return new AuthAuditor(loginHistoryStore, listeners);
    }

    @Bean
    @ConditionalOnMissingBean
    public PermissionResolver springAuthPermissionResolver(RoleStore roleStore) {
        return new PermissionResolver(roleStore);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(AuthUserDirectory.class)
    public SessionService springAuthSessionService(RefreshTokenStore refreshTokenStore,
                                                   CredentialsStore credentialsStore,
                                                   AccessTokenRevocationStore revocationStore,
                                                   AuthUserDirectory userDirectory,
                                                   OpaqueTokenFactory tokenFactory,
                                                   JwtIssuer jwtIssuer,
                                                   PermissionResolver permissionResolver,
                                                   AuthAuditor auditor,
                                                   AuthProperties properties,
                                                   Clock clock) {
        return new SessionService(refreshTokenStore, credentialsStore, revocationStore, userDirectory,
                tokenFactory, jwtIssuer, permissionResolver, auditor, properties, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(AuthUserDirectory.class)
    public LoginService springAuthLoginService(AuthUserDirectory userDirectory,
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
        return new LoginService(userDirectory, credentialsStore, mfaCredentialStore, passwordEncoder,
                jwtIssuer, sessionService, auditor, loginGuard, messenger, properties, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(AuthUserDirectory.class)
    public MfaService springAuthMfaService(MfaCredentialStore mfaCredentialStore,
                                           AuthUserDirectory userDirectory,
                                           PurposeTokenVerifier purposeTokenVerifier,
                                           TotpGenerator totpGenerator,
                                           SecretCipher secretCipher,
                                           SessionService sessionService,
                                           AuthAuditor auditor,
                                           AuthProperties properties,
                                           Clock clock) {
        return new MfaService(mfaCredentialStore, userDirectory, purposeTokenVerifier, totpGenerator,
                secretCipher, sessionService, auditor, properties, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(AuthUserDirectory.class)
    public PasswordService springAuthPasswordService(CredentialsStore credentialsStore,
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
        return new PasswordService(credentialsStore, passwordHistoryStore, passwordResetStore,
                userDirectory, passwordEncoder, passwordPolicy, tokenFactory, otpFactory,
                sessionService, messenger, auditor, properties, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(AuthUserDirectory.class)
    public InvitationService springAuthInvitationService(InvitationStore invitationStore,
                                                         AuthUserDirectory userDirectory,
                                                         OpaqueTokenFactory tokenFactory,
                                                         PasswordService passwordService,
                                                         AuthMessenger messenger,
                                                         AuthAuditor auditor,
                                                         AuthProperties properties,
                                                         Clock clock) {
        return new InvitationService(invitationStore, userDirectory, tokenFactory, passwordService,
                messenger, auditor, properties, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleService springAuthRoleService(RoleStore roleStore, Clock clock) {
        return new RoleService(roleStore, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    public LoginHistoryService springAuthLoginHistoryService(LoginHistoryStore loginHistoryStore,
                                                            Clock clock) {
        return new LoginHistoryService(loginHistoryStore, clock);
    }

    /** Service-to-service authentication, off unless explicitly enabled. */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring-auth.internal", name = "enabled", havingValue = "true")
    public InternalTokenService springAuthInternalTokenService(AuthProperties properties,
                                                               ReplayGuard replayGuard,
                                                               Clock clock) {
        return new InternalTokenService(properties.getInternal(), replayGuard, clock);
    }

    /** Logs the settings that are safe in development and risky in production. */
    @Bean
    @ConditionalOnMissingBean
    public SpringAuthStartupReport springAuthStartupReport(AuthProperties properties,
                                                           RateLimiter rateLimiter,
                                                           AccessTokenRevocationStore revocationStore,
                                                           AuthMessenger messenger) {
        return new SpringAuthStartupReport(properties, rateLimiter, revocationStore,
                !(messenger instanceof NoOpAuthMessenger));
    }
}
