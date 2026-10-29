package io.github.springauth.core.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import io.github.springauth.core.port.RateLimiter;

/**
 * Sliding-window rate limiter held in the JVM heap.
 *
 * <p>Timestamps of recent hits are kept per key and pruned on access, which gives a true sliding
 * window rather than the burst-at-the-boundary behaviour of fixed windows.
 *
 * <p><b>Single instance only.</b> Each replica counts on its own, so N replicas multiply the
 * effective quota by N. Fine for a single deployment or local development; behind a load balancer,
 * use the Redis-backed limiter the starter registers when Spring Data Redis is present.
 */
public class InMemoryRateLimiter implements RateLimiter {

    /** Above this many tracked keys, the oldest idle ones are dropped to bound memory. */
    private static final int MAX_TRACKED_KEYS = 100_000;

    private final Map<String, Deque<Instant>> hits = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryRateLimiter(Clock clock) {
        this.clock = clock;
    }

    @Override
    public boolean tryAcquire(String key, int maxCount, Duration window) {
        Instant now = clock.instant();
        Instant windowStart = now.minus(window);
        if (hits.size() > MAX_TRACKED_KEYS) {
            evictIdleKeys(windowStart);
        }
        Deque<Instant> timestamps = hits.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (timestamps) {
            purgeOlderThan(timestamps, windowStart);
            if (timestamps.size() >= maxCount) {
                return false;
            }
            timestamps.addLast(now);
            return true;
        }
    }

    @Override
    public Duration retryAfter(String key, int maxCount, Duration window) {
        Deque<Instant> timestamps = hits.get(key);
        if (timestamps == null) {
            return Duration.ZERO;
        }
        synchronized (timestamps) {
            Instant oldest = timestamps.peekFirst();
            if (oldest == null) {
                return Duration.ZERO;
            }
            // The quota frees up when the oldest hit leaves the window.
            Duration remaining = Duration.between(clock.instant(), oldest.plus(window));
            return remaining.isNegative() ? Duration.ZERO : remaining;
        }
    }

    private static void purgeOlderThan(Deque<Instant> timestamps, Instant windowStart) {
        while (!timestamps.isEmpty() && timestamps.peekFirst().isBefore(windowStart)) {
            timestamps.removeFirst();
        }
    }

    private void evictIdleKeys(Instant windowStart) {
        hits.entrySet().removeIf(entry -> {
            Deque<Instant> timestamps = entry.getValue();
            synchronized (timestamps) {
                purgeOlderThan(timestamps, windowStart);
                return timestamps.isEmpty();
            }
        });
    }
}
