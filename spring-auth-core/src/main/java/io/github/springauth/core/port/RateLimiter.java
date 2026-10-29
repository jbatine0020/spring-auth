package io.github.springauth.core.port;

import java.time.Duration;

/**
 * Per-key request quota over a sliding window.
 *
 * <p>Keys are usually endpoint plus client address. This is the coarse outer barrier against
 * credential stuffing; per-account lock-out handles the distributed attacker that rotates
 * addresses.
 */
public interface RateLimiter {

    /**
     * Consumes one token.
     *
     * @return true when the call is allowed, false when the quota is exhausted
     */
    boolean tryAcquire(String key, int maxCount, Duration window);

    /** How long to wait before retrying, for the {@code Retry-After} header. */
    Duration retryAfter(String key, int maxCount, Duration window);
}
