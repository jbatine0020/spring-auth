package io.github.springauth.core.model;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialsTest {

    private static final AuthUserId USER = AuthUserId.of("user-1");
    private static final Instant NOW = Instant.parse("2026-03-01T10:00:00Z");
    private static final LockoutPolicy POLICY = new LockoutPolicy(5, Duration.ofMinutes(15));

    @Test
    @DisplayName("locks exactly on the configured attempt, not before")
    void recordFailedAttempt_locksAtThreshold() {
        Credentials credentials = Credentials.create(USER, "hash", false, NOW);

        for (int attempt = 1; attempt < POLICY.maxAttempts(); attempt++) {
            assertThat(credentials.recordFailedAttempt(POLICY, NOW))
                    .as("attempt %d must not lock", attempt)
                    .isFalse();
            assertThat(credentials.isLockedAt(NOW)).isFalse();
        }

        assertThat(credentials.recordFailedAttempt(POLICY, NOW)).isTrue();
        assertThat(credentials.isLockedAt(NOW)).isTrue();
        assertThat(credentials.getLockedUntil()).isEqualTo(NOW.plus(POLICY.duration()));
    }

    @Test
    @DisplayName("reports the lock only once, so the owner is alerted a single time")
    void recordFailedAttempt_reportsLockOnlyOnce() {
        Credentials credentials = Credentials.create(USER, "hash", false, NOW);
        for (int attempt = 0; attempt < POLICY.maxAttempts(); attempt++) {
            credentials.recordFailedAttempt(POLICY, NOW);
        }

        assertThat(credentials.recordFailedAttempt(POLICY, NOW)).isFalse();
    }

    @Test
    @DisplayName("stops counting while locked")
    void recordFailedAttempt_whileLocked_doesNotCount() {
        Credentials credentials = Credentials.create(USER, "hash", false, NOW);
        for (int attempt = 0; attempt < POLICY.maxAttempts(); attempt++) {
            credentials.recordFailedAttempt(POLICY, NOW);
        }
        int attemptsAtLock = credentials.getFailedAttempts();

        credentials.recordFailedAttempt(POLICY, NOW);

        assertThat(credentials.getFailedAttempts()).isEqualTo(attemptsAtLock);
    }

    @Test
    @DisplayName("unlocks on its own once the window passes")
    void isLockedAt_afterWindow_false() {
        Credentials credentials = Credentials.create(USER, "hash", false, NOW);
        for (int attempt = 0; attempt < POLICY.maxAttempts(); attempt++) {
            credentials.recordFailedAttempt(POLICY, NOW);
        }

        assertThat(credentials.isLockedAt(NOW.plus(POLICY.duration()).plusSeconds(1))).isFalse();
    }

    @Test
    @DisplayName("clears the counter on a successful authentication")
    void recordSuccessfulAuthentication_resetsCounter() {
        Credentials credentials = Credentials.create(USER, "hash", false, NOW);
        credentials.recordFailedAttempt(POLICY, NOW);
        credentials.recordFailedAttempt(POLICY, NOW);

        credentials.recordSuccessfulAuthentication(NOW);

        assertThat(credentials.getFailedAttempts()).isZero();
        assertThat(credentials.getLockedUntil()).isNull();
    }

    @Test
    @DisplayName("a self-service change satisfies the forced-change flag")
    void changePassword_clearsMustChange() {
        Credentials credentials = Credentials.create(USER, "hash", true, NOW);

        credentials.changePassword("new-hash", NOW.plusSeconds(60));

        assertThat(credentials.isMustChangePassword()).isFalse();
        assertThat(credentials.getPasswordHash()).isEqualTo("new-hash");
        assertThat(credentials.requiresPasswordChange(NOW.plusSeconds(60), null)).isFalse();
    }

    @Test
    @DisplayName("an administrative reset forces a change at the next login")
    void resetByAdministrator_setsMustChange() {
        Credentials credentials = Credentials.create(USER, "hash", false, NOW);

        credentials.resetByAdministrator("new-hash", NOW);

        assertThat(credentials.isMustChangePassword()).isTrue();
        assertThat(credentials.requiresPasswordChange(NOW, null)).isTrue();
    }

    @Test
    @DisplayName("an aged password requires a change even without the flag")
    void requiresPasswordChange_expiredPassword_true() {
        Credentials credentials = Credentials.create(USER, "hash", false, NOW);
        Duration maxAge = Duration.ofDays(90);

        assertThat(credentials.requiresPasswordChange(NOW.plus(Duration.ofDays(89)), maxAge)).isFalse();
        assertThat(credentials.requiresPasswordChange(NOW.plus(Duration.ofDays(91)), maxAge)).isTrue();
    }

    @Test
    @DisplayName("a zero or null max age disables expiry")
    void requiresPasswordChange_noMaxAge_false() {
        Credentials credentials = Credentials.create(USER, "hash", false, NOW);
        Instant muchLater = NOW.plus(Duration.ofDays(3650));

        assertThat(credentials.requiresPasswordChange(muchLater, null)).isFalse();
        assertThat(credentials.requiresPasswordChange(muchLater, Duration.ZERO)).isFalse();
    }

    @Test
    @DisplayName("an administrative unlock clears the lock immediately")
    void unlock_clearsLock() {
        Credentials credentials = Credentials.create(USER, "hash", false, NOW);
        for (int attempt = 0; attempt < POLICY.maxAttempts(); attempt++) {
            credentials.recordFailedAttempt(POLICY, NOW);
        }

        credentials.unlock(NOW);

        assertThat(credentials.isLockedAt(NOW)).isFalse();
        assertThat(credentials.getFailedAttempts()).isZero();
    }
}
