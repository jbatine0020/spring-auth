package io.github.springauth.core.port;

import java.time.Duration;
import java.util.OptionalLong;

import io.github.springauth.core.model.AuthUserId;

/**
 * Cuts short access tokens that are still cryptographically valid.
 *
 * <p>A JWT cannot be withdrawn once signed, so revocation works by remembering an instant per
 * user: every token issued before that instant is refused. Since access tokens are short-lived,
 * the record only has to survive one TTL plus a small skew, which makes an expiring key store the
 * natural backing.
 *
 * <p>The in-memory default is per-instance. Behind more than one replica, use the Redis adapter
 * the starter wires automatically when {@code StringRedisTemplate} is on the classpath, otherwise
 * a logout only takes effect on the instance that handled it.
 */
public interface AccessTokenRevocationStore {

    /**
     * Marks every token issued before {@code revokedSinceEpochSeconds} as invalid.
     *
     * @param ttl how long to keep the mark; must outlive the longest access token still in flight
     */
    void revokeSince(AuthUserId userId, long revokedSinceEpochSeconds, Duration ttl);

    /**
     * @param userId subject of the token being checked
     * @return the revocation instant when one is recorded, empty otherwise
     */
    OptionalLong revokedSinceEpochSeconds(String userId);
}
