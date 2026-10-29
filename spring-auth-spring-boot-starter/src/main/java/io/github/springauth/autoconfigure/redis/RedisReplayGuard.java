package io.github.springauth.autoconfigure.redis;

import java.time.Duration;

import io.github.springauth.core.port.ReplayGuard;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Replay guard shared by every instance.
 *
 * <p>Built on {@code SET key value NX PX ttl}, which is atomic: two concurrent replays of the same
 * identifier cannot both win, whichever instances handle them.
 *
 * <p>Required behind more than one replica. With the in-memory guard, a token replayed against a
 * different instance simply goes through.
 */
public class RedisReplayGuard implements ReplayGuard {

    private static final String KEY_PREFIX = "spring-auth:replay:";
    private static final String MARKER = "1";

    private final StringRedisTemplate redis;

    public RedisReplayGuard(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public boolean registerIfAbsent(String identifier, Duration ttl) {
        Boolean firstUse = redis.opsForValue().setIfAbsent(KEY_PREFIX + identifier, MARKER, ttl);
        // A null answer means the command could not be confirmed. Refusing is the safe reading:
        // rejecting a legitimate internal call is recoverable, accepting a replay is not.
        return Boolean.TRUE.equals(firstUse);
    }
}
