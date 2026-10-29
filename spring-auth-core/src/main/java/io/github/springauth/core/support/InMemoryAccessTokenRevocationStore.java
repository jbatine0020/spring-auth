package io.github.springauth.core.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.OptionalLong;
import java.util.concurrent.ConcurrentHashMap;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.port.AccessTokenRevocationStore;

/**
 * Revocation stamps held in the JVM heap, with their own expiry.
 *
 * <p><b>Single instance only.</b> A logout handled by one replica leaves the other replicas
 * accepting the token until it expires on its own. Use the Redis adapter as soon as there is more
 * than one instance.
 */
public class InMemoryAccessTokenRevocationStore implements AccessTokenRevocationStore {

    private final Map<String, Stamp> stamps = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryAccessTokenRevocationStore(Clock clock) {
        this.clock = clock;
    }

    @Override
    public void revokeSince(AuthUserId userId, long revokedSinceEpochSeconds, Duration ttl) {
        stamps.put(userId.value(), new Stamp(revokedSinceEpochSeconds, clock.instant().plus(ttl)));
    }

    @Override
    public OptionalLong revokedSinceEpochSeconds(String userId) {
        Stamp stamp = stamps.get(userId);
        if (stamp == null) {
            return OptionalLong.empty();
        }
        if (stamp.expiresAt().isBefore(clock.instant())) {
            stamps.remove(userId, stamp);
            return OptionalLong.empty();
        }
        return OptionalLong.of(stamp.revokedSinceEpochSeconds());
    }

    private record Stamp(long revokedSinceEpochSeconds, Instant expiresAt) {}
}
