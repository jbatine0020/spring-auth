package io.github.springauth.core.jwt;

import java.security.KeyPair;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;

import com.nimbusds.jwt.SignedJWT;
import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtIssuerTest {

    private static final Instant NOW = Instant.parse("2026-03-01T10:00:00Z");

    private final AuthProperties properties = new AuthProperties();
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final JwtKeyProvider keyProvider = new JwtKeyProvider("", "", "kid-1", "", "", false);
    private final JwtIssuer issuer = new JwtIssuer(keyProvider, properties.getJwt(), clock);
    private final PurposeTokenVerifier verifier =
            new PurposeTokenVerifier(keyProvider, properties.getJwt(), clock);

    private final AuthUser user = AuthUser.builder(AuthUserId.of("user-1"), "alex@example.com")
            .email("alex@example.com")
            .tenantId("tenant-9")
            .build();

    @Test
    @DisplayName("an access token carries the registered and application claims")
    void issueAccessToken_carriesClaims() throws ParseException {
        JwtIssuer.IssuedToken issued = issuer.issueAccessToken(user, Set.of("orders:read"), false);

        SignedJWT jwt = SignedJWT.parse(issued.token());
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("user-1");
        assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo(properties.getJwt().getIssuer());
        assertThat(jwt.getJWTClaimsSet().getAudience()).contains(properties.getJwt().getAudience());
        assertThat(jwt.getJWTClaimsSet().getStringClaim("email")).isEqualTo("alex@example.com");
        assertThat(jwt.getJWTClaimsSet().getStringClaim("tenant_id")).isEqualTo("tenant-9");
        assertThat(jwt.getJWTClaimsSet().getStringListClaim("permissions"))
                .containsExactly("orders:read");
        assertThat(jwt.getJWTClaimsSet().getJWTID()).isNotBlank();
        assertThat(issued.expiresAt()).isEqualTo(NOW.plus(properties.getJwt().getAccessTtl()));
    }

    @Test
    @DisplayName("omits the forced-change claim when it does not apply")
    void issueAccessToken_withoutMustChange_omitsTheClaim() throws ParseException {
        JwtIssuer.IssuedToken issued = issuer.issueAccessToken(user, Set.of(), false);

        assertThat(SignedJWT.parse(issued.token()).getJWTClaimsSet()
                .getClaim("must_change_password")).isNull();
    }

    @Test
    @DisplayName("emits the forced-change claim when it applies")
    void issueAccessToken_mustChange_setsTheClaim() throws ParseException {
        JwtIssuer.IssuedToken issued = issuer.issueAccessToken(user, Set.of(), true);

        assertThat(SignedJWT.parse(issued.token()).getJWTClaimsSet()
                .getBooleanClaim("must_change_password")).isTrue();
    }

    @Test
    @DisplayName("omits the tenant claim for a user without a tenant")
    void issueAccessToken_withoutTenant_omitsTheClaim() throws ParseException {
        AuthUser plain = AuthUser.of(AuthUserId.of("user-2"), "plain@example.com", "plain@example.com");

        JwtIssuer.IssuedToken issued = issuer.issueAccessToken(plain, Set.of(), false);

        assertThat(SignedJWT.parse(issued.token()).getJWTClaimsSet().getClaim("tenant_id")).isNull();
    }

    @Test
    @DisplayName("an access token carries no purpose claim")
    void issueAccessToken_hasNoPurpose() throws ParseException {
        JwtIssuer.IssuedToken issued = issuer.issueAccessToken(user, Set.of(), false);

        assertThat(SignedJWT.parse(issued.token()).getJWTClaimsSet()
                .getClaim(TokenPurpose.CLAIM)).isNull();
    }

    @Test
    @DisplayName("a purpose token is only valid for its own purpose")
    void purposeToken_isNotInterchangeable() {
        JwtIssuer.IssuedToken challenge = issuer.issuePurposeToken(
                user.id(), TokenPurpose.MFA_CHALLENGE, Duration.ofMinutes(5));

        assertThat(verifier.verify(challenge.token(), TokenPurpose.MFA_CHALLENGE))
                .contains(user.id());
        assertThat(verifier.verify(challenge.token(), TokenPurpose.MFA_ENROLLMENT)).isEmpty();
    }

    @Test
    @DisplayName("an expired purpose token is refused")
    void purposeToken_expired_refused() {
        JwtIssuer.IssuedToken challenge = issuer.issuePurposeToken(
                user.id(), TokenPurpose.MFA_CHALLENGE, Duration.ofMinutes(5));
        PurposeTokenVerifier laterVerifier = new PurposeTokenVerifier(keyProvider,
                properties.getJwt(), Clock.fixed(NOW.plus(Duration.ofMinutes(6)), ZoneOffset.UTC));

        assertThat(laterVerifier.verify(challenge.token(), TokenPurpose.MFA_CHALLENGE)).isEmpty();
    }

    @Test
    @DisplayName("a token signed by another key is refused")
    void purposeToken_foreignSignature_refused() {
        JwtKeyProvider otherProvider = new JwtKeyProvider("", "", "kid-2", "", "", false);
        JwtIssuer otherIssuer = new JwtIssuer(otherProvider, properties.getJwt(), clock);
        JwtIssuer.IssuedToken foreign = otherIssuer.issuePurposeToken(
                user.id(), TokenPurpose.MFA_CHALLENGE, Duration.ofMinutes(5));

        assertThat(verifier.verify(foreign.token(), TokenPurpose.MFA_CHALLENGE)).isEmpty();
    }

    @Test
    @DisplayName("garbage input is refused without throwing")
    void purposeToken_garbage_refused() {
        assertThat(verifier.verify("not-a-jwt", TokenPurpose.MFA_CHALLENGE)).isEmpty();
        assertThat(verifier.verify(null, TokenPurpose.MFA_CHALLENGE)).isEmpty();
        assertThat(verifier.verify("", TokenPurpose.MFA_CHALLENGE)).isEmpty();
    }

    @Test
    @DisplayName("the JWKS holds one key, or two while a rotation is in flight")
    void jwkSet_containsCurrentAndPreviousKeys() {
        assertThat(keyProvider.getJwkSet().getKeys()).hasSize(1);

        KeyPair previous = JwtKeyProvider.generateKeyPair();
        String previousPublic = Base64.getEncoder().encodeToString(previous.getPublic().getEncoded());
        JwtKeyProvider rotating = new JwtKeyProvider("", "", "kid-new", previousPublic, "kid-old", false);

        assertThat(rotating.getJwkSet().getKeys()).hasSize(2);
        assertThat(rotating.getJwkSetJson()).doesNotContain("\"d\"");
    }

    @Test
    @DisplayName("a rotation without the previous key id is refused")
    void keyProvider_previousKeyWithoutId_throws() {
        KeyPair previous = JwtKeyProvider.generateKeyPair();
        String previousPublic = Base64.getEncoder().encodeToString(previous.getPublic().getEncoded());

        assertThatThrownBy(() -> new JwtKeyProvider("", "", "kid-new", previousPublic, "", false))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("previous-key-id");
    }

    @Test
    @DisplayName("a half-configured key pair is refused")
    void keyProvider_privateKeyWithoutPublic_throws() {
        assertThatThrownBy(() -> new JwtKeyProvider("private-only", "", "kid", "", "", false))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("provided together");
    }

    @Test
    @DisplayName("refuses to start without persistent keys when they are mandatory")
    void keyProvider_requiresPersistentKeys_throws() {
        assertThatThrownBy(() -> new JwtKeyProvider("", "", "", "", "", true))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("mandatory");
    }

    @Test
    @DisplayName("a persistent key pair round-trips through its base64 form")
    void keyProvider_loadsExportedKeys() {
        String[] exported = JwtKeyProvider.exportKeyPair(JwtKeyProvider.generateKeyPair());

        JwtKeyProvider loaded = new JwtKeyProvider(exported[0], exported[1], "kid", "", "", true);
        JwtIssuer loadedIssuer = new JwtIssuer(loaded, properties.getJwt(), clock);
        PurposeTokenVerifier loadedVerifier =
                new PurposeTokenVerifier(loaded, properties.getJwt(), clock);
        JwtIssuer.IssuedToken token = loadedIssuer.issuePurposeToken(
                user.id(), TokenPurpose.MFA_CHALLENGE, Duration.ofMinutes(5));

        Optional<AuthUserId> subject = loadedVerifier.verify(token.token(), TokenPurpose.MFA_CHALLENGE);
        assertThat(subject).contains(user.id());
    }
}
