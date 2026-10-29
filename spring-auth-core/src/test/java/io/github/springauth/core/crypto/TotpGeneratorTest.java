package io.github.springauth.core.crypto;

import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TotpGeneratorTest {

    private final TotpGenerator generator = new TotpGenerator();

    private static final Instant NOW = Instant.parse("2026-03-01T10:00:00Z");

    @Nested
    @DisplayName("code generation")
    class CodeGeneration {

        @Test
        @DisplayName("produces a code of the requested length, zero-padded")
        void generateCode_returnsPaddedCode() {
            byte[] secret = TotpGenerator.base32Decode(generator.generateBase32Secret());

            String code = generator.generateCode(secret, 1_000L, 6);

            assertThat(code).hasSize(6).containsOnlyDigits();
        }

        @Test
        @DisplayName("is deterministic for a given secret and counter")
        void generateCode_isDeterministic() {
            byte[] secret = TotpGenerator.base32Decode(generator.generateBase32Secret());

            assertThat(generator.generateCode(secret, 42L, 6))
                    .isEqualTo(generator.generateCode(secret, 42L, 6));
        }

        @Test
        @DisplayName("generates a 32-character base32 secret")
        void generateBase32Secret_returns160Bits() {
            String secret = generator.generateBase32Secret();

            assertThat(secret).hasSize(32).matches("[A-Z2-7]+");
            assertThat(TotpGenerator.base32Decode(secret)).hasSize(TotpGenerator.SECRET_BYTES);
        }
    }

    @Nested
    @DisplayName("verification")
    class Verification {

        @Test
        @DisplayName("accepts the code of the current step and returns its counter")
        void verifyCode_currentStep_accepted() {
            String secret = generator.generateBase32Secret();
            long counter = NOW.getEpochSecond() / TotpGenerator.STEP_SECONDS;
            String code = generator.generateCode(TotpGenerator.base32Decode(secret), counter, 6);

            Optional<Long> accepted = generator.verifyCode(
                    secret, code, TotpGenerator.NEVER_USED, NOW, 6, 1);

            assertThat(accepted).contains(counter);
        }

        @Test
        @DisplayName("tolerates one step of clock drift either side")
        void verifyCode_withinWindow_accepted() {
            String secret = generator.generateBase32Secret();
            long currentCounter = NOW.getEpochSecond() / TotpGenerator.STEP_SECONDS;
            String previousStepCode = generator.generateCode(
                    TotpGenerator.base32Decode(secret), currentCounter - 1, 6);

            Optional<Long> accepted = generator.verifyCode(
                    secret, previousStepCode, TotpGenerator.NEVER_USED, NOW, 6, 1);

            assertThat(accepted).contains(currentCounter - 1);
        }

        @Test
        @DisplayName("refuses a code outside the tolerated window")
        void verifyCode_outsideWindow_refused() {
            String secret = generator.generateBase32Secret();
            long currentCounter = NOW.getEpochSecond() / TotpGenerator.STEP_SECONDS;
            String staleCode = generator.generateCode(
                    TotpGenerator.base32Decode(secret), currentCounter - 5, 6);

            Optional<Long> accepted = generator.verifyCode(
                    secret, staleCode, TotpGenerator.NEVER_USED, NOW, 6, 1);

            assertThat(accepted).isEmpty();
        }

        @Test
        @DisplayName("refuses a code whose counter was already consumed")
        void verifyCode_replayedCounter_refused() {
            String secret = generator.generateBase32Secret();
            long counter = NOW.getEpochSecond() / TotpGenerator.STEP_SECONDS;
            String code = generator.generateCode(TotpGenerator.base32Decode(secret), counter, 6);

            // First use succeeds and yields the counter the caller must persist.
            assertThat(generator.verifyCode(secret, code, TotpGenerator.NEVER_USED, NOW, 6, 1))
                    .contains(counter);

            // Same code, same step, but the counter is now known: this is the replay case a
            // passive observer would attempt.
            assertThat(generator.verifyCode(secret, code, counter, NOW, 6, 1)).isEmpty();
        }

        @Test
        @DisplayName("refuses a code of the wrong shape without touching the secret")
        void verifyCode_malformed_refused() {
            String secret = generator.generateBase32Secret();

            assertThat(generator.verifyCode(secret, "12345", TotpGenerator.NEVER_USED, NOW, 6, 1))
                    .isEmpty();
            assertThat(generator.verifyCode(secret, "abcdef", TotpGenerator.NEVER_USED, NOW, 6, 1))
                    .isEmpty();
            assertThat(generator.verifyCode(secret, null, TotpGenerator.NEVER_USED, NOW, 6, 1))
                    .isEmpty();
        }

        @Test
        @DisplayName("refuses a code computed from another secret")
        void verifyCode_foreignSecret_refused() {
            String secret = generator.generateBase32Secret();
            String otherSecret = generator.generateBase32Secret();
            long counter = NOW.getEpochSecond() / TotpGenerator.STEP_SECONDS;
            String foreignCode = generator.generateCode(
                    TotpGenerator.base32Decode(otherSecret), counter, 6);

            assertThat(generator.verifyCode(secret, foreignCode, TotpGenerator.NEVER_USED, NOW, 6, 1))
                    .isEmpty();
        }

        @Test
        @DisplayName("rejects a missing secret outright")
        void verifyCode_noSecret_throws() {
            assertThatThrownBy(() -> generator.verifyCode(null, "123456", -1L))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("otpauth URI")
    class OtpauthUri {

        @Test
        @DisplayName("carries issuer, account, secret and the algorithm parameters")
        void buildOtpauthUri_containsEverythingAnAuthenticatorNeeds() {
            String secret = generator.generateBase32Secret();

            String uri = generator.buildOtpauthUri("My App", "alex@example.com", secret);

            assertThat(uri)
                    .startsWith("otpauth://totp/")
                    .contains("secret=" + secret)
                    .contains("algorithm=SHA1")
                    .contains("digits=6")
                    .contains("period=30");
        }

        @Test
        @DisplayName("percent-encodes the label so spaces and separators survive")
        void buildOtpauthUri_encodesLabel() {
            String uri = generator.buildOtpauthUri("My App", "alex@example.com",
                    generator.generateBase32Secret());

            assertThat(uri).doesNotContain("My App");
            assertThat(uri).contains("My+App");
        }
    }

    @Test
    @DisplayName("base32 encoding round-trips")
    void base32_roundTrip() {
        byte[] original = new byte[]{0x00, 0x7F, (byte) 0xFF, 0x10, 0x2A};

        assertThat(TotpGenerator.base32Decode(TotpGenerator.base32Encode(original)))
                .startsWith(original);
    }
}
