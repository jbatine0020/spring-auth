package io.github.springauth.autoconfigure.redis;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.ServerSession;
import io.github.springauth.core.port.ServerSessionStore;
import org.springframework.data.redis.core.StringRedisTemplate;

/** Redis hash-backed server sessions. Redis errors are deliberately propagated to fail closed. */
public final class RedisServerSessionStore implements ServerSessionStore {

    private static final String KEY_PREFIX = "spring-auth:session:";
    private final StringRedisTemplate redis;

    public RedisServerSessionStore(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public ServerSession create(AuthUserId userId, Instant now, Instant absoluteExpiresAt) {
        ServerSession session = new ServerSession(UUID.randomUUID(), userId, now, now,
                absoluteExpiresAt, false);
        return save(session);
    }

    @Override
    public Optional<ServerSession> find(UUID sessionId) {
        Map<Object, Object> values = redis.opsForHash().entries(key(sessionId));
        if (values.isEmpty()) return Optional.empty();
        return Optional.of(new ServerSession(sessionId,
                AuthUserId.of((String) values.get("userId")),
                Instant.parse((String) values.get("createdAt")),
                Instant.parse((String) values.get("lastAccessAt")),
                Instant.parse((String) values.get("absoluteExpiresAt")),
                "1".equals(values.get("revoked"))));
    }

    @Override
    public ServerSession save(ServerSession session) {
        String key = key(session.id());
        redis.opsForHash().putAll(key, Map.of(
                "userId", session.userId().value(),
                "createdAt", session.createdAt().toString(),
                "lastAccessAt", session.lastAccessAt().toString(),
                "absoluteExpiresAt", session.absoluteExpiresAt().toString(),
                "revoked", session.revoked() ? "1" : "0"));
        Duration ttl = Duration.between(Instant.now(), session.absoluteExpiresAt());
        if (!ttl.isNegative() && !ttl.isZero()) redis.expire(key, ttl);
        return session;
    }

    @Override
    public int revokeAllForUser(AuthUserId userId, Instant now) {
        Set<String> keys = redis.keys(KEY_PREFIX + "*");
        int revoked = 0;
        if (keys != null) {
            for (String key : keys) {
                Map<Object, Object> values = redis.opsForHash().entries(key);
                if (userId.value().equals(values.get("userId")) && !"1".equals(values.get("revoked"))) {
                    redis.opsForHash().put(key, "revoked", "1");
                    revoked++;
                }
            }
        }
        return revoked;
    }

    private static String key(UUID id) {
        return KEY_PREFIX + id;
    }
}
