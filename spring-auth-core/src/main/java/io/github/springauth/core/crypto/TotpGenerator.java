package io.github.springauth.core.crypto;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * TOTP generator and verifier, RFC 6238 over HOTP (RFC 4226), HMAC-SHA1, 30-second steps.
 *
 * <p>Interoperable with Google Authenticator, Microsoft Authenticator, Authy, 1Password and any
 * other RFC 6238 client. Secrets are handled in base32 (RFC 4648) because that is what the
 * {@code otpauth://} URI and the QR code carry.
 *
 * <p>Two properties matter more than the algorithm itself:
 * <ul>
 *   <li><b>Clock tolerance</b>: a window of ±1 step accepts codes 30 seconds either side of now,
 *       covering ordinary phone drift without widening the guessing surface much.</li>
 *   <li><b>Replay protection</b>: a code stays mathematically valid for its whole step, so it can
 *       be reused by anyone who observes it. {@link #verifyCode} therefore refuses any counter
 *       lower than or equal to the last accepted one, and returns the new counter for the caller
 *       to persist.</li>
 * </ul>
 *
 * <p>Comparison against the expected code is constant-time to avoid leaking a prefix match
 * through timing.
 */
public class TotpGenerator {

    public static final int STEP_SECONDS = 30;
    public static final int DEFAULT_DIGITS = 6;
    public static final int DEFAULT_WINDOW = 1;
    public static final int SECRET_BYTES = 20;

    /** Counter value meaning "no code has ever been accepted for this credential". */
    public static final long NEVER_USED = -1L;

    private static final String HMAC_ALGORITHM = "HmacSHA1";
    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private final SecureRandom random = new SecureRandom();

    /** Draws a 160-bit random secret, base32-encoded (32 characters). */
    public String generateBase32Secret() {
        byte[] bytes = new byte[SECRET_BYTES];
        random.nextBytes(bytes);
        return base32Encode(bytes);
    }

    /**
     * Computes the code for an explicit counter. Exposed mainly so tests and enrolment
     * confirmation flows can derive the expected value.
     */
    public String generateCode(byte[] secret, long counter, int digits) {
        try {
            ByteBuffer buffer = ByteBuffer.allocate(8).putLong(counter);
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
            byte[] hash = mac.doFinal(buffer.array());
            int offset = hash[hash.length - 1] & 0x0F;
            int truncated = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);
            int modulus = (int) Math.pow(10, digits);
            String code = String.valueOf(truncated % modulus);
            return "0".repeat(Math.max(0, digits - code.length())) + code;
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("HMAC-SHA1 computation failed", ex);
        }
    }

    /**
     * Code valid at a given instant for a base32 secret.
     *
     * <p>Provided so that applications can write end-to-end tests against an enrolled factor
     * without reimplementing the algorithm. Never call it on a request path: producing the code
     * server-side defeats the point of a second factor.
     */
    public String codeAt(String base32Secret, Instant now, int digits) {
        return generateCode(base32Decode(base32Secret), now.getEpochSecond() / STEP_SECONDS, digits);
    }

    /** Convenience overload using the current time, 6 digits and a ±1 step window. */
    public Optional<Long> verifyCode(String base32Secret, String code, long lastAcceptedCounter) {
        return verifyCode(base32Secret, code, lastAcceptedCounter,
                Instant.now(), DEFAULT_DIGITS, DEFAULT_WINDOW);
    }

    /**
     * Verifies a code against the shared secret, honouring both the clock window and the
     * replay guard.
     *
     * @param base32Secret        shared secret, base32-encoded
     * @param code                code typed by the user
     * @param lastAcceptedCounter last counter accepted for this credential, {@link #NEVER_USED} if none
     * @param now                 verification instant
     * @param digits              code length
     * @param window              number of steps tolerated either side of {@code now}
     * @return the counter to persist when the code is valid and strictly newer than the last one,
     *         empty when the code is wrong, expired or replayed
     */
    public Optional<Long> verifyCode(String base32Secret, String code, long lastAcceptedCounter,
                                     Instant now, int digits, int window) {
        if (base32Secret == null || base32Secret.isBlank()) {
            throw new IllegalArgumentException("base32Secret is required");
        }
        if (code == null || !code.matches("\\d{" + digits + "}")) {
            return Optional.empty();
        }
        byte[] secret = base32Decode(base32Secret);
        long currentCounter = now.getEpochSecond() / STEP_SECONDS;
        for (int delta = -window; delta <= window; delta++) {
            long candidate = currentCounter + delta;
            // Replay guard: a code from a counter already consumed is refused even though it
            // still hashes correctly for the rest of its step.
            if (candidate <= lastAcceptedCounter) {
                continue;
            }
            if (constantTimeEquals(generateCode(secret, candidate, digits), code)) {
                return Optional.of(candidate);
            }
        }
        return Optional.empty();
    }

    /**
     * Builds the {@code otpauth://totp/...} URI to render as a QR code.
     *
     * @param issuer  application name shown in the authenticator app
     * @param account user-facing account label, typically the email address
     */
    public String buildOtpauthUri(String issuer, String account, String base32Secret) {
        String label = urlEncode(issuer + ":" + account);
        return "otpauth://totp/" + label
                + "?secret=" + base32Secret
                + "&issuer=" + urlEncode(issuer)
                + "&algorithm=SHA1&digits=" + DEFAULT_DIGITS + "&period=" + STEP_SECONDS;
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    static String base32Encode(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        int bits = 0;
        int value = 0;
        for (byte b : bytes) {
            value = (value << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                out.append(BASE32_ALPHABET.charAt((value >> (bits - 5)) & 0x1F));
                bits -= 5;
            }
        }
        if (bits > 0) {
            out.append(BASE32_ALPHABET.charAt((value << (5 - bits)) & 0x1F));
        }
        return out.toString();
    }

    static byte[] base32Decode(String encoded) {
        String cleaned = encoded.replace("=", "").replace(" ", "").toUpperCase();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int buffer = 0;
        int bits = 0;
        for (char c : cleaned.toCharArray()) {
            int index = BASE32_ALPHABET.indexOf(c);
            if (index < 0) {
                throw new IllegalArgumentException("Invalid base32 character: " + c);
            }
            buffer = (buffer << 5) | index;
            bits += 5;
            if (bits >= 8) {
                out.write((buffer >> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }
}
