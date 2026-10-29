package io.github.springauth.core.model;

import java.time.Duration;

/**
 * Brute-force lock-out rule: how many consecutive failures are tolerated and for how long the
 * subject is frozen afterwards.
 *
 * <p>Passed to the aggregates rather than hard-coded in them, so password lock-out and MFA
 * lock-out can be tuned independently while sharing the same behaviour.
 *
 * @param maxAttempts consecutive failures before locking, must be at least 1
 * @param duration    how long the lock lasts
 */
public record LockoutPolicy(int maxAttempts, Duration duration) {

    public LockoutPolicy {
        if (maxAttempts < 1) {
            throw new IllegalArgumentException("maxAttempts must be at least 1, got " + maxAttempts);
        }
        if (duration == null || duration.isNegative() || duration.isZero()) {
            throw new IllegalArgumentException("lockout duration must be strictly positive");
        }
    }
}
