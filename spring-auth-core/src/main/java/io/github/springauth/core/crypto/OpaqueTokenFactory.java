package io.github.springauth.core.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Mints and fingerprints the opaque secrets the library hands out: refresh tokens, password-reset
 * links and invitation links.
 *
 * <p>These are not JWTs. They are 256 bits of {@link SecureRandom} rendered base64url, and only
 * their SHA-256 digest is stored. A database dump therefore yields nothing usable.
 *
 * <p>An unsalted digest is the right choice here, unlike for passwords: the input already has
 * 256 bits of entropy, so there is no dictionary to run and no need for a slow KDF. Salting would
 * only prevent the lookup by hash that verification depends on.
 */
public class OpaqueTokenFactory {

    private static final int TOKEN_BYTES = 32;

    private final SecureRandom random = new SecureRandom();

    /** Generates a fresh 256-bit secret, base64url without padding (43 characters). */
    public String generateRawToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** SHA-256 digest of a raw token, lowercase hex. This is what gets persisted. */
    public String hash(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("rawToken is required");
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable on this JVM", ex);
        }
    }

    /** Constant-time comparison of two digests. */
    public boolean matches(String rawToken, String expectedHash) {
        if (rawToken == null || rawToken.isBlank() || expectedHash == null) {
            return false;
        }
        return MessageDigest.isEqual(
                hash(rawToken).getBytes(StandardCharsets.UTF_8),
                expectedHash.getBytes(StandardCharsets.UTF_8));
    }
}
