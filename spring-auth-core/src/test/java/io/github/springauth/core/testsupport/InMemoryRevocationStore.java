package io.github.springauth.core.testsupport;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.OptionalLong;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.port.AccessTokenRevocationStore;

/** Revocation stamps in a plain map, with no expiry, so tests can assert on them directly. */
public class InMemoryRevocationStore implements AccessTokenRevocationStore {

    private final Map<String, Long> stamps = new HashMap<>();

    @Override
    public void revokeSince(AuthUserId userId, long revokedSinceEpochSeconds, Duration ttl) {
        stamps.put(userId.value(), revokedSinceEpochSeconds);
    }

    @Override
    public OptionalLong revokedSinceEpochSeconds(String userId) {
        Long stamp = stamps.get(userId);
        return stamp == null ? OptionalLong.empty() : OptionalLong.of(stamp);
    }

    public boolean hasStampFor(AuthUserId userId) {
        return stamps.containsKey(userId.value());
    }
}
