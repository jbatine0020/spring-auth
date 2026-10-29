package io.github.springauth.core.support;

import java.time.Duration;

import io.github.springauth.core.testsupport.AuthTestFixture;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryRateLimiterTest {

    private static final Duration WINDOW = Duration.ofMinutes(1);

    private final AuthTestFixture.MutableClock clock =
            new AuthTestFixture.MutableClock(AuthTestFixture.START);
    private final InMemoryRateLimiter limiter = new InMemoryRateLimiter(clock);

    @Test
    @DisplayName("allows exactly the quota, then refuses")
    void tryAcquire_beyondQuota_refused() {
        for (int call = 0; call < 3; call++) {
            assertThat(limiter.tryAcquire("login|10.0.0.1", 3, WINDOW)).isTrue();
        }

        assertThat(limiter.tryAcquire("login|10.0.0.1", 3, WINDOW)).isFalse();
    }

    @Test
    @DisplayName("counts each key independently")
    void tryAcquire_perKey() {
        limiter.tryAcquire("login|10.0.0.1", 1, WINDOW);

        assertThat(limiter.tryAcquire("login|10.0.0.1", 1, WINDOW)).isFalse();
        assertThat(limiter.tryAcquire("login|10.0.0.2", 1, WINDOW)).isTrue();
    }

    @Test
    @DisplayName("frees the quota as the window slides")
    void tryAcquire_afterWindow_allowedAgain() {
        limiter.tryAcquire("login|10.0.0.1", 1, WINDOW);
        assertThat(limiter.tryAcquire("login|10.0.0.1", 1, WINDOW)).isFalse();

        clock.advance(WINDOW.plusSeconds(1));

        assertThat(limiter.tryAcquire("login|10.0.0.1", 1, WINDOW)).isTrue();
    }

    @Test
    @DisplayName("frees the quota progressively, not all at once")
    void tryAcquire_slidingWindow_freesOneSlotAtATime() {
        limiter.tryAcquire("login|10.0.0.1", 2, WINDOW);
        clock.advance(Duration.ofSeconds(30));
        limiter.tryAcquire("login|10.0.0.1", 2, WINDOW);
        assertThat(limiter.tryAcquire("login|10.0.0.1", 2, WINDOW)).isFalse();

        // The first hit leaves the window; the second is still inside it.
        clock.advance(Duration.ofSeconds(31));

        assertThat(limiter.tryAcquire("login|10.0.0.1", 2, WINDOW)).isTrue();
        assertThat(limiter.tryAcquire("login|10.0.0.1", 2, WINDOW)).isFalse();
    }

    @Test
    @DisplayName("reports how long to wait")
    void retryAfter_reportsRemainingTime() {
        limiter.tryAcquire("login|10.0.0.1", 1, WINDOW);
        clock.advance(Duration.ofSeconds(20));

        assertThat(limiter.retryAfter("login|10.0.0.1", 1, WINDOW))
                .isBetween(Duration.ofSeconds(39), Duration.ofSeconds(40));
    }

    @Test
    @DisplayName("reports no wait for an unknown key")
    void retryAfter_unknownKey_isZero() {
        assertThat(limiter.retryAfter("never-seen", 1, WINDOW)).isZero();
    }
}
