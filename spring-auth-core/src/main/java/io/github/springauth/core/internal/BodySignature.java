package io.github.springauth.core.internal;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC-SHA256 over a request body, for webhooks and callbacks.
 *
 * <p>Complements the internal token rather than replacing it: the token says who is calling, the
 * signature says the payload was not altered on the way. Useful whenever a third party posts to
 * an endpoint that cannot present a token.
 *
 * <p>Comparison is constant-time. A naive {@code equals} on hex strings leaks, through timing, how
 * many leading characters were right, which is enough to reconstruct a signature byte by byte.
 */
public final class BodySignature {

    private static final String ALGORITHM = "HmacSHA256";

    private BodySignature() {
        // utility
    }

    /** Lowercase hex HMAC of {@code body} under {@code secret}. */
    public static String sign(String secret, byte[] body) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("secret is required");
        }
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), ALGORITHM));
            return HexFormat.of().formatHex(mac.doFinal(body == null ? new byte[0] : body));
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("HMAC-SHA256 computation failed", ex);
        }
    }

    /**
     * Constant-time verification.
     *
     * @param providedSignature value from the signature header, with or without a {@code sha256=} prefix
     */
    public static boolean verify(String secret, byte[] body, String providedSignature) {
        if (providedSignature == null || providedSignature.isBlank()) {
            return false;
        }
        String normalised = providedSignature.startsWith("sha256=")
                ? providedSignature.substring("sha256=".length())
                : providedSignature;
        String expected = sign(secret, body);
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                normalised.trim().toLowerCase().getBytes(StandardCharsets.UTF_8));
    }
}
