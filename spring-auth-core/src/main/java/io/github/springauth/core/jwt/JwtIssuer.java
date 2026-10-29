package io.github.springauth.core.jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;

/**
 * Mints RS256-signed access tokens and the short-lived tokens used mid-authentication.
 *
 * <p>Access tokens carry the registered claims of RFC 7519 ({@code iss}, {@code sub}, {@code aud},
 * {@code iat}, {@code exp}, {@code jti}) plus the application ones: {@code email}, the permission
 * list, an optional tenant discriminator, and {@code must_change_password} when the account is
 * flagged. Claim names for permissions and tenant are configurable so the token fits an existing
 * gateway contract.
 *
 * <p>Refresh tokens are not issued here: they are opaque random secrets, see
 * {@link io.github.springauth.core.crypto.OpaqueTokenFactory}.
 */
public class JwtIssuer {

    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_MUST_CHANGE_PASSWORD = "must_change_password";

    private final JwtKeyProvider keyProvider;
    private final AuthProperties.Jwt properties;
    private final Clock clock;

    public JwtIssuer(JwtKeyProvider keyProvider, AuthProperties.Jwt properties, Clock clock) {
        this.keyProvider = Objects.requireNonNull(keyProvider, "keyProvider is required");
        this.properties = Objects.requireNonNull(properties, "properties is required");
        this.clock = Objects.requireNonNull(clock, "clock is required");
    }

    /**
     * Issues a full access token.
     *
     * @param user               authenticated principal
     * @param permissions        effective permissions, emitted in the configured claim
     * @param mustChangePassword adds the enforcement claim read by the must-change-password filter
     */
    public IssuedToken issueAccessToken(AuthUser user,
                                        Collection<String> permissions,
                                        boolean mustChangePassword) {
        Objects.requireNonNull(user, "user is required");
        Instant now = clock.instant();
        Instant expiry = now.plus(properties.getAccessTtl());

        JWTClaimsSet.Builder claims = baseClaims(user.id().value(), now, expiry)
                .claim(properties.getPermissionClaim(), permissions == null ? java.util.List.of() : permissions);

        if (user.email() != null && !user.email().isBlank()) {
            claims.claim(CLAIM_EMAIL, user.email());
        }
        // Tenant claim only exists for tenant-scoped users, so downstream code can rely on
        // "claim present" meaning "scoped caller" without a second lookup.
        if (user.tenantId() != null && !user.tenantId().isBlank()) {
            claims.claim(properties.getTenantClaim(), user.tenantId());
        }
        // Emitted only when true: an absent claim is unambiguous, a false one invites a
        // truthiness bug on the consuming side.
        if (mustChangePassword) {
            claims.claim(CLAIM_MUST_CHANGE_PASSWORD, true);
        }
        for (Map.Entry<String, Object> extra : user.extraClaims().entrySet()) {
            claims.claim(extra.getKey(), extra.getValue());
        }

        return sign(claims.build(), expiry, properties.getAccessTtl());
    }

    /**
     * Issues a token that proves one authentication step was cleared, and nothing more.
     *
     * <p>It is signed by the same key as an access token but carries a {@code purpose} claim,
     * which the resource server refuses as a bearer credential.
     */
    public IssuedToken issuePurposeToken(AuthUserId userId, TokenPurpose purpose, Duration ttl) {
        Objects.requireNonNull(userId, "userId is required");
        Objects.requireNonNull(purpose, "purpose is required");
        Instant now = clock.instant();
        Instant expiry = now.plus(ttl);
        JWTClaimsSet claims = baseClaims(userId.value(), now, expiry)
                .claim(TokenPurpose.CLAIM, purpose.claimValue())
                .build();
        return sign(claims, expiry, ttl);
    }

    public Duration getAccessTtl() {
        return properties.getAccessTtl();
    }

    public String getIssuer() {
        return properties.getIssuer();
    }

    public String getAudience() {
        return properties.getAudience();
    }

    private JWTClaimsSet.Builder baseClaims(String subject, Instant issuedAt, Instant expiry) {
        return new JWTClaimsSet.Builder()
                .issuer(properties.getIssuer())
                .subject(subject)
                .audience(properties.getAudience())
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiry))
                .jwtID(UUID.randomUUID().toString());
    }

    private IssuedToken sign(JWTClaimsSet claims, Instant expiry, Duration ttl) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(JOSEObjectType.JWT)
                    .keyID(keyProvider.getKeyId())
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new RSASSASigner(keyProvider.getPrivateKey()));
            return new IssuedToken(jwt.serialize(), expiry, ttl.toSeconds());
        } catch (JOSEException ex) {
            throw new IllegalStateException("JWT signing failed", ex);
        }
    }

    /**
     * @param token            compact serialisation, to hand to the client
     * @param expiresAt        absolute expiry
     * @param expiresInSeconds relative expiry, as OAuth2 clients expect it
     */
    public record IssuedToken(String token, Instant expiresAt, long expiresInSeconds) {}
}
