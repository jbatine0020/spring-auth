package io.github.springauth.core.jwt;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Holds the RSA key pair used to sign access tokens, and publishes the matching JWKS.
 *
 * <p><b>Persistent keys (production).</b> Supply {@code private-key} (PKCS#8, base64) and
 * {@code public-key} (X.509 SubjectPublicKeyInfo, base64). Tokens then survive restarts and
 * several instances of the same service validate each other's tokens.
 *
 * <p><b>Ephemeral keys (local development).</b> With no key configured a 2048-bit pair is drawn
 * at boot and a warning is logged: every previously issued token becomes invalid on restart. Set
 * {@code require-persistent-keys=true} in any deployed environment to turn that convenience into
 * a startup failure.
 *
 * <p><b>Rotation.</b> Publishing {@code previous-public-key} alongside its {@code previous-key-id}
 * keeps the old key in the JWKS while signing with the new one, so tokens minted before the switch
 * stay valid until they expire. Only the current private key is ever loaded: the previous one is
 * neither needed nor accepted, which is what makes the rotation one-way.
 */
public class JwtKeyProvider {

    private static final Logger log = LoggerFactory.getLogger(JwtKeyProvider.class);
    private static final int KEY_SIZE = 2048;

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final String keyId;
    private final JWKSet jwkSet;

    public JwtKeyProvider(String privateKeyBase64,
                          String publicKeyBase64,
                          String configuredKeyId,
                          String previousPublicKeyBase64,
                          String previousKeyId,
                          boolean requirePersistentKeys) {
        boolean hasPrivate = isPresent(privateKeyBase64);
        boolean hasPublic = isPresent(publicKeyBase64);
        if (hasPrivate != hasPublic) {
            throw new IllegalStateException(
                    "spring-auth.jwt.private-key and spring-auth.jwt.public-key must be provided together");
        }
        if (requirePersistentKeys && !hasPrivate) {
            throw new IllegalStateException(
                    "spring-auth.jwt.private-key / public-key are mandatory when require-persistent-keys=true");
        }

        if (hasPrivate) {
            this.privateKey = decodePrivate(privateKeyBase64.trim());
            this.publicKey = decodePublic(publicKeyBase64.trim(), "spring-auth.jwt.public-key");
            log.info("spring-auth: JWT key pair loaded from configuration");
        } else {
            log.warn("spring-auth: JWT key pair generated EPHEMERALLY at boot, every issued token "
                    + "becomes invalid on restart. Configure spring-auth.jwt.private-key / public-key "
                    + "outside local development.");
            KeyPair pair = generateKeyPair();
            this.privateKey = (RSAPrivateKey) pair.getPrivate();
            this.publicKey = (RSAPublicKey) pair.getPublic();
        }

        this.keyId = isPresent(configuredKeyId) ? configuredKeyId.trim() : UUID.randomUUID().toString();
        this.jwkSet = buildJwkSet(previousPublicKeyBase64, previousKeyId);
    }

    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public String getKeyId() {
        return keyId;
    }

    /** Current key, plus the previous one while a rotation is in flight. */
    public JWKSet getJwkSet() {
        return jwkSet;
    }

    /** Serialises the JWKS for the {@code /.well-known/jwks.json} endpoint, public keys only. */
    public String getJwkSetJson() {
        return jwkSet.toString();
    }

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(KEY_SIZE);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("RSA unavailable on this JVM", ex);
        }
    }

    /**
     * Renders a freshly generated key pair as the two base64 properties to configure.
     * Bootstrap helper for a new deployment.
     */
    public static String[] exportKeyPair(KeyPair pair) {
        return new String[]{
                Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())
        };
    }

    private JWKSet buildJwkSet(String previousPublicKeyBase64, String previousKeyId) {
        List<JWK> keys = new ArrayList<>();
        keys.add(new RSAKey.Builder(publicKey).keyID(keyId).build());
        if (isPresent(previousPublicKeyBase64)) {
            if (!isPresent(previousKeyId)) {
                throw new IllegalStateException(
                        "spring-auth.jwt.previous-key-id is required when previous-public-key is set");
            }
            String previousKid = previousKeyId.trim();
            if (previousKid.equals(keyId)) {
                throw new IllegalStateException(
                        "spring-auth.jwt.previous-key-id must differ from key-id");
            }
            RSAPublicKey previous = decodePublic(
                    previousPublicKeyBase64.trim(), "spring-auth.jwt.previous-public-key");
            keys.add(new RSAKey.Builder(previous).keyID(previousKid).build());
        }
        return new JWKSet(keys);
    }

    private static boolean isPresent(String value) {
        return value != null && !value.isBlank();
    }

    private static RSAPrivateKey decodePrivate(String base64) {
        try {
            byte[] bytes = Base64.getDecoder().decode(base64);
            return (RSAPrivateKey) KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(bytes));
        } catch (IllegalArgumentException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new IllegalStateException(
                    "spring-auth.jwt.private-key is invalid (base64-encoded PKCS#8 expected)", ex);
        }
    }

    private static RSAPublicKey decodePublic(String base64, String propertyName) {
        try {
            byte[] bytes = Base64.getDecoder().decode(base64);
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(bytes));
        } catch (IllegalArgumentException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new IllegalStateException(
                    propertyName + " is invalid (base64-encoded X.509 SubjectPublicKeyInfo expected)", ex);
        }
    }
}
