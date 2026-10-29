package io.github.springauth.core.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Every knob of the library, bound from {@code spring-auth.*}.
 *
 * <p>Defaults are chosen to be safe in production rather than convenient in development: strong
 * password rules, short access tokens, MFA lock-out enabled, rate limiting on. The two values with
 * no usable default are {@code jwt.private-key}/{@code public-key} and {@code crypto.master-key};
 * everything else works out of the box.
 *
 * <p>See {@code docs/configuration.md} for the full reference table.
 */
@ConfigurationProperties(prefix = "spring-auth")
public class AuthProperties {

    private final Jwt jwt = new Jwt();
    private final Crypto crypto = new Crypto();
    private final Password password = new Password();
    private final Mfa mfa = new Mfa();
    private final Otp otp = new Otp();
    private final Session session = new Session();
    private final PasswordReset passwordReset = new PasswordReset();
    private final Invitation invitation = new Invitation();
    private final RateLimit rateLimit = new RateLimit();
    private final Web web = new Web();
    private final Internal internal = new Internal();

    public Jwt getJwt() {
        return jwt;
    }

    public Crypto getCrypto() {
        return crypto;
    }

    public Password getPassword() {
        return password;
    }

    public Mfa getMfa() {
        return mfa;
    }

    public Otp getOtp() {
        return otp;
    }

    public Session getSession() {
        return session;
    }

    public PasswordReset getPasswordReset() {
        return passwordReset;
    }

    public Invitation getInvitation() {
        return invitation;
    }

    public RateLimit getRateLimit() {
        return rateLimit;
    }

    public Web getWeb() {
        return web;
    }

    public Internal getInternal() {
        return internal;
    }

    /** Access token signing and validation. */
    public static class Jwt {

        /** {@code iss} claim of issued tokens, and the value validated on incoming ones. */
        private String issuer = "spring-auth";

        /** {@code aud} claim of issued tokens. */
        private String audience = "spring-auth";

        /** Access token lifetime. Short on purpose: revocation relies on expiry. */
        private Duration accessTtl = Duration.ofMinutes(5);

        /** Signing key, base64-encoded PKCS#8. Empty means "generate an ephemeral pair at boot". */
        private String privateKey = "";

        /** Verification key, base64-encoded X.509 SubjectPublicKeyInfo. */
        private String publicKey = "";

        /** {@code kid} advertised in the JWKS. A random UUID is used when empty. */
        private String keyId = "";

        /** Previous verification key, kept in the JWKS during a rotation. */
        private String previousPublicKey = "";

        /** {@code kid} of the previous key. Required as soon as previousPublicKey is set. */
        private String previousKeyId = "";

        /** Refuse to start without persistent keys. Turn on everywhere but local development. */
        private boolean requirePersistentKeys = false;

        /** Claim carrying the permission list. */
        private String permissionClaim = "permissions";

        /** Claim carrying the tenant discriminator, omitted when the user has no tenant. */
        private String tenantClaim = "tenant_id";

        /**
         * Grace added to the access TTL when stamping a revocation, so the stamp outlives every
         * token issued just before it.
         */
        private Duration revocationSkew = Duration.ofSeconds(30);

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public Duration getAccessTtl() {
            return accessTtl;
        }

        public void setAccessTtl(Duration accessTtl) {
            this.accessTtl = accessTtl;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }

        public String getPreviousPublicKey() {
            return previousPublicKey;
        }

        public void setPreviousPublicKey(String previousPublicKey) {
            this.previousPublicKey = previousPublicKey;
        }

        public String getPreviousKeyId() {
            return previousKeyId;
        }

        public void setPreviousKeyId(String previousKeyId) {
            this.previousKeyId = previousKeyId;
        }

        public boolean isRequirePersistentKeys() {
            return requirePersistentKeys;
        }

        public void setRequirePersistentKeys(boolean requirePersistentKeys) {
            this.requirePersistentKeys = requirePersistentKeys;
        }

        public String getPermissionClaim() {
            return permissionClaim;
        }

        public void setPermissionClaim(String permissionClaim) {
            this.permissionClaim = permissionClaim;
        }

        public String getTenantClaim() {
            return tenantClaim;
        }

        public void setTenantClaim(String tenantClaim) {
            this.tenantClaim = tenantClaim;
        }

        public Duration getRevocationSkew() {
            return revocationSkew;
        }

        public void setRevocationSkew(Duration revocationSkew) {
            this.revocationSkew = revocationSkew;
        }
    }

    /** Symmetric encryption of stored secrets. */
    public static class Crypto {

        /**
         * Base64-encoded AES-256 key protecting TOTP seeds at rest. Mandatory as soon as MFA is
         * used. Generate one with {@code SecretCipher.generateMasterKey()}.
         */
        private String masterKey = "";

        public String getMasterKey() {
            return masterKey;
        }

        public void setMasterKey(String masterKey) {
            this.masterKey = masterKey;
        }
    }

    /** Password policy, hashing cost and brute-force lock-out. */
    public static class Password {

        private int minLength = 12;
        private boolean requireUppercase = true;
        private boolean requireLowercase = true;
        private boolean requireDigit = true;
        private boolean requireSpecial = true;

        /** BCrypt cost. 12 is roughly 250 ms per hash on a modern laptop. */
        private int bcryptCost = 12;

        /** How many past passwords are refused on change. 0 disables the check. */
        private int historySize = 5;

        /** Forces a change once the password is older than this. Zero disables expiry. */
        private Duration maxAge = Duration.ZERO;

        /** Consecutive failures before the account locks. */
        private int maxFailedAttempts = 5;

        /** How long the account stays locked. */
        private Duration lockoutDuration = Duration.ofMinutes(15);

        public int getMinLength() {
            return minLength;
        }

        public void setMinLength(int minLength) {
            this.minLength = minLength;
        }

        public boolean isRequireUppercase() {
            return requireUppercase;
        }

        public void setRequireUppercase(boolean requireUppercase) {
            this.requireUppercase = requireUppercase;
        }

        public boolean isRequireLowercase() {
            return requireLowercase;
        }

        public void setRequireLowercase(boolean requireLowercase) {
            this.requireLowercase = requireLowercase;
        }

        public boolean isRequireDigit() {
            return requireDigit;
        }

        public void setRequireDigit(boolean requireDigit) {
            this.requireDigit = requireDigit;
        }

        public boolean isRequireSpecial() {
            return requireSpecial;
        }

        public void setRequireSpecial(boolean requireSpecial) {
            this.requireSpecial = requireSpecial;
        }

        public int getBcryptCost() {
            return bcryptCost;
        }

        public void setBcryptCost(int bcryptCost) {
            this.bcryptCost = bcryptCost;
        }

        public int getHistorySize() {
            return historySize;
        }

        public void setHistorySize(int historySize) {
            this.historySize = historySize;
        }

        public Duration getMaxAge() {
            return maxAge;
        }

        public void setMaxAge(Duration maxAge) {
            this.maxAge = maxAge;
        }

        public int getMaxFailedAttempts() {
            return maxFailedAttempts;
        }

        public void setMaxFailedAttempts(int maxFailedAttempts) {
            this.maxFailedAttempts = maxFailedAttempts;
        }

        public Duration getLockoutDuration() {
            return lockoutDuration;
        }

        public void setLockoutDuration(Duration lockoutDuration) {
            this.lockoutDuration = lockoutDuration;
        }
    }

    /** TOTP second factor and step-up confirmation. */
    public static class Mfa {

        /** Label shown in the authenticator app next to the account. */
        private String issuerLabel = "spring-auth";

        private int digits = 6;

        /** Steps of 30 s tolerated either side of now. */
        private int window = 1;

        private int maxFailedAttempts = 5;
        private Duration lockoutDuration = Duration.ofMinutes(15);

        /** Lifetime of the token bridging the password step and the TOTP step. */
        private Duration challengeTtl = Duration.ofMinutes(5);

        /** Lifetime of the token allowing a first enrolment. */
        private Duration enrollmentTtl = Duration.ofMinutes(10);

        /** Enables {@code @RequiresStepUp} enforcement. */
        private boolean stepUpEnabled = true;

        /** Header carrying the step-up code. */
        private String stepUpHeader = "X-Mfa-Code";

        public String getIssuerLabel() {
            return issuerLabel;
        }

        public void setIssuerLabel(String issuerLabel) {
            this.issuerLabel = issuerLabel;
        }

        public int getDigits() {
            return digits;
        }

        public void setDigits(int digits) {
            this.digits = digits;
        }

        public int getWindow() {
            return window;
        }

        public void setWindow(int window) {
            this.window = window;
        }

        public int getMaxFailedAttempts() {
            return maxFailedAttempts;
        }

        public void setMaxFailedAttempts(int maxFailedAttempts) {
            this.maxFailedAttempts = maxFailedAttempts;
        }

        public Duration getLockoutDuration() {
            return lockoutDuration;
        }

        public void setLockoutDuration(Duration lockoutDuration) {
            this.lockoutDuration = lockoutDuration;
        }

        public Duration getChallengeTtl() {
            return challengeTtl;
        }

        public void setChallengeTtl(Duration challengeTtl) {
            this.challengeTtl = challengeTtl;
        }

        public Duration getEnrollmentTtl() {
            return enrollmentTtl;
        }

        public void setEnrollmentTtl(Duration enrollmentTtl) {
            this.enrollmentTtl = enrollmentTtl;
        }

        public boolean isStepUpEnabled() {
            return stepUpEnabled;
        }

        public void setStepUpEnabled(boolean stepUpEnabled) {
            this.stepUpEnabled = stepUpEnabled;
        }

        public String getStepUpHeader() {
            return stepUpHeader;
        }

        public void setStepUpHeader(String stepUpHeader) {
            this.stepUpHeader = stepUpHeader;
        }
    }

    /** Short-lived one-time codes delivered by e-mail or SMS after password verification. */
    public static class Otp {

        private Duration ttl = Duration.ofMinutes(5);
        private Duration resendCooldown = Duration.ofSeconds(60);
        private int maxAttempts = 5;
        private int maxSendPerHour = 5;

        public Duration getTtl() { return ttl; }
        public void setTtl(Duration ttl) { this.ttl = ttl; }
        public Duration getResendCooldown() { return resendCooldown; }
        public void setResendCooldown(Duration resendCooldown) { this.resendCooldown = resendCooldown; }
        public int getMaxAttempts() { return maxAttempts; }
        public void setMaxAttempts(int maxAttempts) { this.maxAttempts = maxAttempts; }
        public int getMaxSendPerHour() { return maxSendPerHour; }
        public void setMaxSendPerHour(int maxSendPerHour) { this.maxSendPerHour = maxSendPerHour; }
    }

    /** Refresh tokens and session lifetime. */
    public static class Session {

        private Duration refreshTtl = Duration.ofDays(30);
        private Duration inactivityTtl = Duration.ofMinutes(30);
        private Duration absoluteTtl = Duration.ofHours(8);

        /**
         * Serves the refresh token as an HttpOnly cookie in addition to the response body.
         * Recommended for browser clients: JavaScript cannot read it, so an XSS cannot steal it.
         */
        private boolean refreshCookieEnabled = false;

        private String refreshCookieName = "refresh_token";
        private String refreshCookiePath = "/api";
        private boolean refreshCookieSecure = true;
        private String refreshCookieSameSite = "Strict";

        public Duration getRefreshTtl() {
            return refreshTtl;
        }

        public void setRefreshTtl(Duration refreshTtl) {
            this.refreshTtl = refreshTtl;
        }

        public Duration getInactivityTtl() {
            return inactivityTtl;
        }

        public void setInactivityTtl(Duration inactivityTtl) {
            this.inactivityTtl = inactivityTtl;
        }

        public Duration getAbsoluteTtl() {
            return absoluteTtl;
        }

        public void setAbsoluteTtl(Duration absoluteTtl) {
            this.absoluteTtl = absoluteTtl;
        }

        public boolean isRefreshCookieEnabled() {
            return refreshCookieEnabled;
        }

        public void setRefreshCookieEnabled(boolean refreshCookieEnabled) {
            this.refreshCookieEnabled = refreshCookieEnabled;
        }

        public String getRefreshCookieName() {
            return refreshCookieName;
        }

        public void setRefreshCookieName(String refreshCookieName) {
            this.refreshCookieName = refreshCookieName;
        }

        public String getRefreshCookiePath() {
            return refreshCookiePath;
        }

        public void setRefreshCookiePath(String refreshCookiePath) {
            this.refreshCookiePath = refreshCookiePath;
        }

        public boolean isRefreshCookieSecure() {
            return refreshCookieSecure;
        }

        public void setRefreshCookieSecure(boolean refreshCookieSecure) {
            this.refreshCookieSecure = refreshCookieSecure;
        }

        public String getRefreshCookieSameSite() {
            return refreshCookieSameSite;
        }

        public void setRefreshCookieSameSite(String refreshCookieSameSite) {
            this.refreshCookieSameSite = refreshCookieSameSite;
        }
    }

    /** Forgotten-password flow: emailed link plus an SMS code. */
    public static class PasswordReset {

        private boolean enabled = true;

        /** Validity of the reset link. */
        private Duration linkTtl = Duration.ofMinutes(30);

        private int otpDigits = 6;

        /** Wrong codes tolerated on one link before it locks. */
        private int maxAttempts = 5;

        /**
         * Requires the SMS code on top of the emailed link. Turn off only when the application
         * has no phone number for its users; the link alone is then the single factor.
         */
        private boolean requireOtp = true;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public Duration getLinkTtl() {
            return linkTtl;
        }

        public void setLinkTtl(Duration linkTtl) {
            this.linkTtl = linkTtl;
        }

        public int getOtpDigits() {
            return otpDigits;
        }

        public void setOtpDigits(int otpDigits) {
            this.otpDigits = otpDigits;
        }

        public int getMaxAttempts() {
            return maxAttempts;
        }

        public void setMaxAttempts(int maxAttempts) {
            this.maxAttempts = maxAttempts;
        }

        public boolean isRequireOtp() {
            return requireOtp;
        }

        public void setRequireOtp(boolean requireOtp) {
            this.requireOtp = requireOtp;
        }
    }

    /** One-shot invitation links used to onboard a user. */
    public static class Invitation {

        private boolean enabled = true;
        private Duration ttl = Duration.ofDays(7);

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public Duration getTtl() {
            return ttl;
        }

        public void setTtl(Duration ttl) {
            this.ttl = ttl;
        }
    }

    /** Per-IP quotas on the authentication endpoints. */
    public static class RateLimit {

        /** Never disable in production: this is the outer brute-force barrier. */
        private boolean enabled = true;

        private Duration window = Duration.ofMinutes(1);
        private int loginPerMinute = 10;
        private int mfaPerMinute = 10;
        private int refreshPerMinute = 30;
        private int passwordResetPerMinute = 10;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public Duration getWindow() {
            return window;
        }

        public void setWindow(Duration window) {
            this.window = window;
        }

        public int getLoginPerMinute() {
            return loginPerMinute;
        }

        public void setLoginPerMinute(int loginPerMinute) {
            this.loginPerMinute = loginPerMinute;
        }

        public int getMfaPerMinute() {
            return mfaPerMinute;
        }

        public void setMfaPerMinute(int mfaPerMinute) {
            this.mfaPerMinute = mfaPerMinute;
        }

        public int getRefreshPerMinute() {
            return refreshPerMinute;
        }

        public void setRefreshPerMinute(int refreshPerMinute) {
            this.refreshPerMinute = refreshPerMinute;
        }

        public int getPasswordResetPerMinute() {
            return passwordResetPerMinute;
        }

        public void setPasswordResetPerMinute(int passwordResetPerMinute) {
            this.passwordResetPerMinute = passwordResetPerMinute;
        }
    }

    /** REST endpoints and the security filter chain. */
    public static class Web {

        /** Registers the bundled controllers. Turn off to expose your own API on top of the services. */
        private boolean enabled = true;

        /** Prefix of every bundled endpoint. */
        private String basePath = "/api/v1/auth";

        /** Registers the library's SecurityFilterChain. Turn off to keep full control of it. */
        private boolean securityChainEnabled = true;

        /** Publishes {@code /.well-known/jwks.json}. */
        private boolean jwksEnabled = true;

        /** Extra paths left unauthenticated, on top of the library's own public endpoints. */
        private List<String> publicPaths = new ArrayList<>();

        /** Origins allowed by CORS. Empty means CORS is not configured by the library. */
        private List<String> allowedOrigins = new ArrayList<>();

        /** Sends HSTS, CSP and Referrer-Policy headers. */
        private boolean securityHeadersEnabled = true;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getBasePath() {
            return basePath;
        }

        public void setBasePath(String basePath) {
            this.basePath = basePath;
        }

        public boolean isSecurityChainEnabled() {
            return securityChainEnabled;
        }

        public void setSecurityChainEnabled(boolean securityChainEnabled) {
            this.securityChainEnabled = securityChainEnabled;
        }

        public boolean isJwksEnabled() {
            return jwksEnabled;
        }

        public void setJwksEnabled(boolean jwksEnabled) {
            this.jwksEnabled = jwksEnabled;
        }

        public List<String> getPublicPaths() {
            return publicPaths;
        }

        public void setPublicPaths(List<String> publicPaths) {
            this.publicPaths = publicPaths;
        }

        public List<String> getAllowedOrigins() {
            return allowedOrigins;
        }

        public void setAllowedOrigins(List<String> allowedOrigins) {
            this.allowedOrigins = allowedOrigins;
        }

        public boolean isSecurityHeadersEnabled() {
            return securityHeadersEnabled;
        }

        public void setSecurityHeadersEnabled(boolean securityHeadersEnabled) {
            this.securityHeadersEnabled = securityHeadersEnabled;
        }
    }

    /** Service-to-service authentication. */
    public static class Internal {

        private boolean enabled = false;

        /** Identity this service presents when calling a peer. */
        private String serviceId = "";

        /** Header carrying the internal token. */
        private String tokenHeader = "X-Internal-Token";

        /** Header carrying the HMAC signature of the body. */
        private String signatureHeader = "X-Signature";

        /** Lifetime of an internal token. Keep it short: these are machine-to-machine calls. */
        private Duration tokenTtl = Duration.ofMinutes(2);

        /** Shared secrets, keyed by peer service id. */
        private java.util.Map<String, String> peers = new java.util.LinkedHashMap<>();

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getServiceId() {
            return serviceId;
        }

        public void setServiceId(String serviceId) {
            this.serviceId = serviceId;
        }

        public String getTokenHeader() {
            return tokenHeader;
        }

        public void setTokenHeader(String tokenHeader) {
            this.tokenHeader = tokenHeader;
        }

        public String getSignatureHeader() {
            return signatureHeader;
        }

        public void setSignatureHeader(String signatureHeader) {
            this.signatureHeader = signatureHeader;
        }

        public Duration getTokenTtl() {
            return tokenTtl;
        }

        public void setTokenTtl(Duration tokenTtl) {
            this.tokenTtl = tokenTtl;
        }

        public java.util.Map<String, String> getPeers() {
            return peers;
        }

        public void setPeers(java.util.Map<String, String> peers) {
            this.peers = peers;
        }
    }
}
