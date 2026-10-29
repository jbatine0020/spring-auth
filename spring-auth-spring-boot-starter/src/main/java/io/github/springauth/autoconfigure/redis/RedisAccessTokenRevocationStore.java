package io.github.springauth.autoconfigure.redis;

import java.time.Duration;
import java.util.OptionalLong;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.port.AccessTokenRevocationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Revocation stamps shared by every instance.
 *
 * <p>Redis expiry does the housekeeping: a stamp only has to outlive the tokens it invalidates, so
 * it is written with the access TTL plus a small skew and disappears on its own.
 *
 * <p>Required behind more than one replica. With the in-memory store, a logout handled by one
 * instance leaves the others accepting the token until it expires, which is precisely the window
 * revocation exists to close.
 */
public class RedisAccessTokenRevocationStore implements AccessTokenRevocationStore {

    private static final Logger log = LoggerFactory.getLogger(RedisAccessTokenRevocationStore.class);
    private static final String KEY_PREFIX = "spring-auth:revoked-since:";

    private final StringRedisTemplate redis;

    public RedisAccessTokenRevocationStore(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public void revokeSince(AuthUserId userId, long revokedSinceEpochSeconds, Duration ttl) {
        redis.opsForValue().set(KEY_PREFIX + userId.value(),
                Long.toString(revokedSinceEpochSeconds), ttl);
    }

    @Override
    public OptionalLong revokedSinceEpochSeconds(String userId) {
        String raw = redis.opsForValue().get(KEY_PREFIX + userId);
        if (raw == null || raw.isBlank()) {
            return OptionalLong.empty();
        }
        try {
            return OptionalLong.of(Long.parseLong(raw));
        } catch (NumberFormatException ex) {
            log.warn("spring-auth: malformed revocation stamp for subject={}", userId);
            return OptionalLong.empty();
        }
    }
}
