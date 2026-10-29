package io.github.springauth.core.port;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.RefreshToken;

/**
 * Persistence of refresh tokens.
 *
 * <p>{@link #findByTokenHash} must look up <b>including revoked and expired rows</b>: detecting a
 * replay depends on still finding the token that was already rotated. Returning empty for revoked
 * tokens would turn a theft signal into a plain "invalid token".
 */
public interface RefreshTokenStore {

    /** Looks up by digest, whatever the token's state. */
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /**
     * Locks the matching row, including revoked tokens, until the caller's transaction ends.
     * Concurrent refresh operations must observe the state committed by the previous holder.
     */
    Optional<RefreshToken> findByTokenHashForUpdate(String tokenHash);

    RefreshToken save(RefreshToken token);

    /**
     * Revokes every token of a family: the response to a detected replay.
     *
     * @return how many rows were revoked
     */
    int revokeFamily(UUID familyId, Instant at);

    /**
     * Revokes every active token of a user: logout everywhere, password change, administrative
     * lockout.
     *
     * @return how many rows were revoked
     */
    int revokeAllForUser(AuthUserId userId, Instant at);

    /**
     * Housekeeping: drops rows expired before {@code before}. Call it from a scheduled job; the
     * library never deletes on its own.
     *
     * @return how many rows were deleted
     */
    int deleteExpiredBefore(Instant before);
}
