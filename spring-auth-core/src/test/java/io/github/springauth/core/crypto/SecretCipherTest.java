package io.github.springauth.core.crypto;

import java.util.Base64;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecretCipherTest {

    private final SecretCipher cipher = new SecretCipher(SecretCipher.generateMasterKey());

    @Test
    @DisplayName("round-trips a value")
    void encryptThenDecrypt_returnsTheOriginal() {
        String plaintext = "JBSWY3DPEHPK3PXP";

        assertThat(cipher.decrypt(cipher.encrypt(plaintext))).isEqualTo(plaintext);
    }

    @Test
    @DisplayName("produces a different ciphertext every time")
    void encrypt_isNotDeterministic() {
        String plaintext = "JBSWY3DPEHPK3PXP";

        // A fresh IV per encryption is what keeps GCM safe; identical ciphertexts would mean the
        // IV is being reused, which leaks the plaintext relationship.
        assertThat(cipher.encrypt(plaintext)).isNotEqualTo(cipher.encrypt(plaintext));
    }

    @Test
    @DisplayName("detects a tampered ciphertext instead of returning garbage")
    void decrypt_tampered_throws() {
        String encrypted = cipher.encrypt("JBSWY3DPEHPK3PXP");
        int separator = encrypted.indexOf(':');
        String body = encrypted.substring(separator + 1);
        // Flip one character of the ciphertext: the GCM tag must catch it.
        String tampered = encrypted.substring(0, separator + 1)
                + (body.charAt(0) == 'A' ? 'B' : 'A') + body.substring(1);

        assertThatThrownBy(() -> cipher.decrypt(tampered))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("decryption failed");
    }

    @Test
    @DisplayName("refuses to decrypt with a different key")
    void decrypt_wrongKey_throws() {
        String encrypted = cipher.encrypt("JBSWY3DPEHPK3PXP");
        SecretCipher otherCipher = new SecretCipher(SecretCipher.generateMasterKey());

        assertThatThrownBy(() -> otherCipher.decrypt(encrypted))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("refuses a malformed payload")
    void decrypt_malformed_throws() {
        assertThatThrownBy(() -> cipher.decrypt("no-separator-here"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("refuses a missing master key")
    void construction_withoutKey_throws() {
        assertThatThrownBy(() -> new SecretCipher(""))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("master-key is required");
    }

    @Test
    @DisplayName("refuses a key that is not 256 bits")
    void construction_withShortKey_throws() {
        String tooShort = Base64.getEncoder().encodeToString(new byte[16]);

        assertThatThrownBy(() -> new SecretCipher(tooShort))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("32 bytes");
    }

    @Test
    @DisplayName("generates a 256-bit master key")
    void generateMasterKey_returns32Bytes() {
        assertThat(Base64.getDecoder().decode(SecretCipher.generateMasterKey())).hasSize(32);
    }
}
