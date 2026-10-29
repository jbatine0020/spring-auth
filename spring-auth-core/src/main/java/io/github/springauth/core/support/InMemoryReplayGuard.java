package io.github.springauth.core.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import io.github.springauth.core.port.ReplayGuard;

/**
 * Replay guard held in the JVM heap, with per-entry expiry.
 *
 * <p><b>Single instance only.</b> A token replayed against a different replica is not detected.
 * Use the Redis adapter behind a load balancer.
 */
public class InMemoryReplayGuard implements ReplayGuard {

    private final Map<String, Instant> seen = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryReplayGuard(Clock clock) {
        this.clock = clock;
    }

    @Override
    public boolean registerIfAbsent(String identifier, Duration ttl) {
        Instant now = clock.instant();
        purgeExpired(now);
        Instant previous = seen.putIfAbsent(identifier, now.plus(ttl));
        if (previous == null) {
            return true;
        }
        // A stale entry is not a replay: the window it protected has closed, so the slot is
        // reclaimed and the identifier accepted once more.
        if (previous.isBefore(now)) {
            seen.put(identifier, now.plus(ttl));
            return true;
        }
        return false;
    }

    private void purgeExpired(Instant now) {
        seen.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
    }
}
