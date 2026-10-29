package io.github.springauth.core.internal;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.error.InternalAuthException;
import io.github.springauth.core.port.ReplayGuard;

/**
 * Short-lived HS256 tokens authenticating one service to another.
 *
 * <p>Symmetric signing is the right trade-off here, unlike for user tokens: both ends are trusted
 * infrastructure sharing a secret, there is no third party to verify without the ability to sign,
 * and it avoids a key distribution problem for calls that live for two minutes.
 *
 * <p>Three checks make a captured token useless: a short expiry, an audience pinned to the callee
 * (so a token addressed to one service cannot be forwarded to another), and a one-shot {@code jti}
 * enforced by the {@link ReplayGuard}. Signature and expiry alone would leave a replay window wide
 * open to anyone able to observe one call.
 *
 * <p>Secrets are configured per peer in {@code spring-auth.internal.peers}. A missing secret is a
 * refusal, never a fallback.
 */
public class InternalTokenService {

    private static final int MIN_SECRET_LENGTH = 32;

    private final AuthProperties.Internal properties;
    private final ReplayGuard replayGuard;
    private final Clock clock;

    public InternalTokenService(AuthProperties.Internal properties, ReplayGuard replayGuard, Clock clock) {
        this.properties = properties;
        this.replayGuard = replayGuard;
        this.clock = clock;
        validateSecrets(properties.getPeers());
    }

    /**
     * Mints a token addressed to one specific peer.
     *
     * @param audienceServiceId identifier of the service being called
     * @throws InternalAuthException when no secret is configured for that peer
     */
    public String issueFor(String audienceServiceId) {
        String secret = secretFor(audienceServiceId);
        Instant now = clock.instant();
        Duration ttl = properties.getTokenTtl();
        try {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(properties.getServiceId())
                    .audience(audienceServiceId)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(ttl)))
                    .jwtID(UUID.randomUUID().toString())
                    .build();
            SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
            jwt.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8)));
            return jwt.serialize();
        } catch (JOSEException ex) {
            throw new InternalAuthException("Could not sign internal token: " + ex.getMessage());
        }
    }

    /**
     * Validates an incoming token.
     *
     * @return the caller's identity
     * @throws InternalAuthException on a bad signature, an unknown peer, an expired token, a
     *                               mismatched audience, or a replayed identifier
     */
    public ServiceIdentity validate(String token) {
        if (token == null || token.isBlank()) {
            throw new InternalAuthException("Missing internal token");
        }
        SignedJWT jwt;
        JWTClaimsSet claims;
        try {
            jwt = SignedJWT.parse(token);
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException ex) {
            throw new InternalAuthException("Malformed internal token");
        }

        String peer = claims.getIssuer();
        if (peer == null || peer.isBlank()) {
            throw new InternalAuthException("Internal token without an issuer");
        }
        String secret = secretFor(peer);

        try {
            if (!jwt.verify(new MACVerifier(secret.getBytes(StandardCharsets.UTF_8)))) {
                throw new InternalAuthException("Bad signature on internal token from " + peer);
            }
        } catch (JOSEException ex) {
            throw new InternalAuthException("Could not verify internal token: " + ex.getMessage());
        }

        Date expiry = claims.getExpirationTime();
        if (expiry == null || expiry.toInstant().isBefore(clock.instant())) {
            throw new InternalAuthException("Expired internal token from " + peer);
        }
        // Audience pinning: without it, a token captured on a call to service A could be
        // forwarded to service B, which shares the same peer secret.
        if (claims.getAudience() == null || !claims.getAudience().contains(properties.getServiceId())) {
            throw new InternalAuthException("Internal token from " + peer + " is addressed elsewhere");
        }

        String jti = claims.getJWTID();
        if (jti == null || jti.isBlank()) {
            throw new InternalAuthException("Internal token from " + peer + " has no jti");
        }
        // Remembered slightly longer than the token lives, so the window closes with the token.
        Duration retention = properties.getTokenTtl().plusSeconds(30);
        if (!replayGuard.registerIfAbsent("spring-auth:internal-jti:" + jti, retention)) {
            throw new InternalAuthException("Replayed internal token from " + peer);
        }

        return new ServiceIdentity(peer);
    }

    private String secretFor(String serviceId) {
        String secret = properties.getPeers().get(serviceId);
        if (secret == null || secret.isBlank()) {
            throw new InternalAuthException("No shared secret configured for peer " + serviceId);
        }
        return secret;
    }

    private static void validateSecrets(Map<String, String> peers) {
        peers.forEach((peer, secret) -> {
            if (secret == null || secret.length() < MIN_SECRET_LENGTH) {
                throw new IllegalStateException("spring-auth.internal.peers." + peer
                        + " must be at least " + MIN_SECRET_LENGTH
                        + " characters (HS256 requires a 256-bit key)");
            }
        });
    }
}
