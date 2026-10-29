package io.github.springauth.core.jwt;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.model.AuthUserId;

/**
 * Validates the short-lived {@code purpose} tokens issued between authentication steps.
 *
 * <p>Checks signature, issuer, audience, expiry and, above all, that the
 * {@code purpose} claim is exactly the one the caller expects. Without that last check a token
 * minted to start an enrolment would also pass the TOTP verification step.
 *
 * <p>Returns an empty {@link Optional} for every failure instead of throwing: callers turn that
 * into one single generic error, so a probing client cannot tell a bad signature from an expired
 * token.
 */
public class PurposeTokenVerifier {

    private final JwtKeyProvider keyProvider;
    private final AuthProperties.Jwt properties;
    private final Clock clock;

    public PurposeTokenVerifier(JwtKeyProvider keyProvider, AuthProperties.Jwt properties, Clock clock) {
        this.keyProvider = Objects.requireNonNull(keyProvider, "keyProvider is required");
        this.properties = Objects.requireNonNull(properties, "properties is required");
        this.clock = Objects.requireNonNull(clock, "clock is required");
    }

    /**
     * @return the subject when the token is valid and carries {@code expectedPurpose}, empty otherwise
     */
    public Optional<AuthUserId> verify(String token, TokenPurpose expectedPurpose) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (!jwt.verify(new RSASSAVerifier(keyProvider.getPublicKey()))) {
                return Optional.empty();
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (!expectedPurpose.claimValue().equals(claims.getStringClaim(TokenPurpose.CLAIM))) {
                return Optional.empty();
            }
            if (!properties.getIssuer().equals(claims.getIssuer())) {
                return Optional.empty();
            }
            if (claims.getAudience() == null || !claims.getAudience().contains(properties.getAudience())) {
                return Optional.empty();
            }
            Date expiry = claims.getExpirationTime();
            if (expiry == null || expiry.toInstant().isBefore(Instant.now(clock))) {
                return Optional.empty();
            }
            String subject = claims.getSubject();
            return subject == null || subject.isBlank()
                    ? Optional.empty()
                    : Optional.of(AuthUserId.of(subject));
        } catch (ParseException | JOSEException | IllegalArgumentException ex) {
            return Optional.empty();
        }
    }
}
