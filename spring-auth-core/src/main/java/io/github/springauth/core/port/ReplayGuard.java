package io.github.springauth.core.port;

import java.time.Duration;

/**
 * Single-use enforcement for identifiers that must never be accepted twice: the {@code jti} of
 * service-to-service tokens, above all.
 *
 * <p>Signature and expiry alone do not stop an intercepted internal token from being replayed
 * within its window. Remembering the identifier for the length of that window does.
 *
 * <p>Entries only need to outlive the token that carries them, so an expiring store is the right
 * backing. The in-memory default is per-instance: behind several replicas, use the Redis adapter,
 * otherwise a token replayed against another instance goes through.
 */
public interface ReplayGuard {

    /**
     * Registers an identifier as consumed.
     *
     * @param ttl how long to remember it; at least the token lifetime
     * @return true when the identifier was unseen, false when it is a replay
     */
    boolean registerIfAbsent(String identifier, Duration ttl);
}
