package io.github.springauth.core.model;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MfaCredentialTest {

    private static final AuthUserId USER = AuthUserId.of("user-1");
    private static final Instant NOW = Instant.parse("2026-03-01T10:00:00Z");
    private static final LockoutPolicy POLICY = new LockoutPolicy(5, Duration.ofMinutes(15));

    @Test
    @DisplayName("a fresh enrolment does not count as a configured factor")
    void enroll_isNotConfirmedYet() {
        MfaCredential credential = MfaCredential.enroll(USER, "cipher", NOW);

        assertThat(credential.isConfirmed()).isFalse();
        assertThat(credential.status()).isEqualTo(MfaStatus.NOT_CONFIGURED);
    }

    @Test
    @DisplayName("the first valid code confirms the factor")
    void recordSuccessfulVerification_confirmsOnFirstSuccess() {
        MfaCredential credential = MfaCredential.enroll(USER, "cipher", NOW);

        credential.recordSuccessfulVerification(100L, NOW);

        assertThat(credential.isConfirmed()).isTrue();
        assertThat(credential.status()).isEqualTo(MfaStatus.CONFIGURED);
        assertThat(credential.getConfirmedAt()).isEqualTo(NOW);
    }

    @Test
    @DisplayName("keeps the original confirmation instant on later verifications")
    void recordSuccessfulVerification_keepsFirstConfirmationInstant() {
        MfaCredential credential = MfaCredential.enroll(USER, "cipher", NOW);
        credential.recordSuccessfulVerification(100L, NOW);

        credential.recordSuccessfulVerification(101L, NOW.plusSeconds(30));

        assertThat(credential.getConfirmedAt()).isEqualTo(NOW);
    }

    @Test
    @DisplayName("refuses a counter that is not strictly newer")
    void recordSuccessfulVerification_replayedCounter_throws() {
        MfaCredential credential = MfaCredential.enroll(USER, "cipher", NOW);
        credential.recordSuccessfulVerification(100L, NOW);

        assertThatThrownBy(() -> credential.recordSuccessfulVerification(100L, NOW))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not newer");
    }

    @Test
    @DisplayName("locks verification at the configured threshold")
    void recordFailedAttempt_locksAtThreshold() {
        MfaCredential credential = MfaCredential.enroll(USER, "cipher", NOW);

        for (int attempt = 1; attempt < POLICY.maxAttempts(); attempt++) {
            assertThat(credential.recordFailedAttempt(POLICY, NOW)).isFalse();
        }

        assertThat(credential.recordFailedAttempt(POLICY, NOW)).isTrue();
        assertThat(credential.isLockedAt(NOW)).isTrue();
    }

    @Test
    @DisplayName("a valid code clears the lock and the counter")
    void recordSuccessfulVerification_clearsLockout() {
        MfaCredential credential = MfaCredential.enroll(USER, "cipher", NOW);
        credential.recordFailedAttempt(POLICY, NOW);
        credential.recordFailedAttempt(POLICY, NOW);

        credential.recordSuccessfulVerification(100L, NOW);

        assertThat(credential.getFailedAttempts()).isZero();
        assertThat(credential.getLockedUntil()).isNull();
    }

    @Test
    @DisplayName("an administrative reset rewinds the replay counter and marks the reset")
    void rotateSecret_resetsEverything() {
        MfaCredential credential = MfaCredential.enroll(USER, "cipher", NOW);
        credential.recordSuccessfulVerification(500L, NOW);

        credential.rotateSecret("new-cipher", NOW.plusSeconds(60));

        assertThat(credential.getEncryptedSecret()).isEqualTo("new-cipher");
        assertThat(credential.getLastAcceptedCounter()).isEqualTo(-1L);
        assertThat(credential.isConfirmed()).isFalse();
        assertThat(credential.status()).isEqualTo(MfaStatus.RESET_PENDING);
    }

    @Test
    @DisplayName("a self-service re-enrolment leaves no reset marker")
    void replaceSecret_hasNoResetMarker() {
        MfaCredential credential = MfaCredential.enroll(USER, "cipher", NOW);
        credential.recordSuccessfulVerification(500L, NOW);

        credential.replaceSecret("new-cipher", NOW.plusSeconds(60));

        assertThat(credential.status()).isEqualTo(MfaStatus.NOT_CONFIGURED);
        assertThat(credential.getLastAcceptedCounter()).isEqualTo(-1L);
    }

    @Test
    @DisplayName("confirming after a reset clears the pending state")
    void recordSuccessfulVerification_afterReset_clearsPending() {
        MfaCredential credential = MfaCredential.enroll(USER, "cipher", NOW);
        credential.rotateSecret("new-cipher", NOW);

        credential.recordSuccessfulVerification(10L, NOW.plusSeconds(60));

        assertThat(credential.status()).isEqualTo(MfaStatus.CONFIGURED);
        assertThat(credential.getResetRequestedAt()).isNull();
    }
}
