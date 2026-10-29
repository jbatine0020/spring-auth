package io.github.springauth.core.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM encryption of application secrets at rest: TOTP seeds, above all.
 *
 * <p>GCM is authenticated encryption: the 128-bit tag makes any tampering with the stored
 * ciphertext fail loudly at decryption instead of yielding garbage. A fresh 12-byte IV is drawn
 * per encryption, which is what keeps GCM safe; never reuse one with the same key.
 *
 * <p>Storage format is a single string, {@code base64(iv) + ":" + base64(ciphertext||tag)}, so a
 * plain {@code varchar} column is enough.
 *
 * <p>The master key is a 32-byte value supplied base64-encoded. Generate one with
 * {@link #generateMasterKey()} and keep it in your secret manager: losing it makes every enrolled
 * factor unreadable, and leaking it makes them all forgeable.
 */
public class SecretCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;
    private static final int KEY_LENGTH = 32;

    private final SecretKeySpec masterKey;
    private final SecureRandom random = new SecureRandom();

    /**
     * @param masterKeyBase64 base64-encoded 256-bit key
     * @throws IllegalStateException when the key is missing or not exactly 32 bytes once decoded
     */
    public SecretCipher(String masterKeyBase64) {
        if (masterKeyBase64 == null || masterKeyBase64.isBlank()) {
            throw new IllegalStateException(
                    "spring-auth.crypto.master-key is required (base64-encoded AES-256 key, 32 bytes)");
        }
        byte[] key;
        try {
            key = Base64.getDecoder().decode(masterKeyBase64.trim());
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("spring-auth.crypto.master-key is not valid base64", ex);
        }
        if (key.length != KEY_LENGTH) {
            throw new IllegalStateException(
                    "spring-auth.crypto.master-key must decode to exactly " + KEY_LENGTH
                            + " bytes (256 bits), got " + key.length);
        }
        this.masterKey = new SecretKeySpec(key, "AES");
    }

    /** Encrypts a UTF-8 string into {@code base64(iv):base64(ciphertext)}. */
    public String encrypt(String plaintext) {
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext is required");
        }
        try {
            byte[] iv = new byte[IV_LENGTH];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(ciphertext);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("AES-GCM encryption failed", ex);
        }
    }

    /**
     * Decrypts a value produced by {@link #encrypt(String)}.
     *
     * @throws IllegalStateException when the key is wrong or the ciphertext was altered
     */
    public String decrypt(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            throw new IllegalArgumentException("encoded is required");
        }
        int separator = encoded.indexOf(':');
        if (separator <= 0 || separator == encoded.length() - 1) {
            throw new IllegalArgumentException(
                    "Malformed ciphertext, expected base64(iv):base64(ciphertext)");
        }
        try {
            byte[] iv = Base64.getDecoder().decode(encoded.substring(0, separator));
            byte[] ciphertext = Base64.getDecoder().decode(encoded.substring(separator + 1));
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(TAG_BITS, iv));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("AES-GCM decryption failed (wrong key or altered data)", ex);
        }
    }

    /** Generates a fresh base64-encoded AES-256 master key. Bootstrap helper. */
    public static String generateMasterKey() {
        byte[] key = new byte[KEY_LENGTH];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
