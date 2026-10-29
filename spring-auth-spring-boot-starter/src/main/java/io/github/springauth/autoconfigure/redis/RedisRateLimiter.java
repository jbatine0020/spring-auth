package io.github.springauth.autoconfigure.redis;

import java.time.Clock;
import java.time.Duration;
import java.util.Set;
import java.util.UUID;

import io.github.springauth.core.port.RateLimiter;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ZSetOperations;

/**
 * Sliding-window rate limiter shared by every instance, backed by a Redis sorted set.
 *
 * <p>Each hit is a member scored with its timestamp. Counting means dropping members older than
 * the window and measuring what is left, which gives a true sliding window rather than the
 * burst-at-the-boundary behaviour of a fixed one.
 *
 * <p>This is what the in-memory limiter cannot do: behind N replicas, per-instance counting
 * multiplies the effective quota by N, and an attacker spreading requests across the load balancer
 * gets exactly that multiple.
 */
public class RedisRateLimiter implements RateLimiter {

    private static final String KEY_PREFIX = "spring-auth:rate-limit:";

    private final StringRedisTemplate redis;
    private final Clock clock;

    public RedisRateLimiter(StringRedisTemplate redis, Clock clock) {
        this.redis = redis;
        this.clock = clock;
    }

    @Override
    public boolean tryAcquire(String key, int maxCount, Duration window) {
        String redisKey = KEY_PREFIX + key;
        long now = clock.millis();
        long windowStart = now - window.toMillis();

        ZSetOperations<String, String> zset = redis.opsForZSet();
        zset.removeRangeByScore(redisKey, 0, windowStart);
        Long count = zset.zCard(redisKey);
        if (count != null && count >= maxCount) {
            return false;
        }
        // The member must be unique: two hits within the same millisecond would otherwise collapse
        // into one and hand out a free request.
        zset.add(redisKey, now + ":" + UUID.randomUUID(), now);
        // Refreshed on every hit so an idle key expires on its own instead of leaking.
        redis.expire(redisKey, window.plusSeconds(1));
        return true;
    }

    @Override
    public Duration retryAfter(String key, int maxCount, Duration window) {
        String redisKey = KEY_PREFIX + key;
        Set<ZSetOperations.TypedTuple<String>> oldest =
                redis.opsForZSet().rangeWithScores(redisKey, 0, 0);
        if (oldest == null || oldest.isEmpty()) {
            return Duration.ZERO;
        }
        Double score = oldest.iterator().next().getScore();
        if (score == null) {
            return Duration.ZERO;
        }
        // The quota frees up when the oldest hit leaves the window.
        long freesUpAt = score.longValue() + window.toMillis();
        long remaining = freesUpAt - clock.millis();
        return remaining <= 0 ? Duration.ZERO : Duration.ofMillis(remaining);
    }
}
