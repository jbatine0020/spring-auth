package io.github.springauth.core.port;

import java.time.Instant;
import java.util.List;

import io.github.springauth.core.model.AuthUserId;

/**
 * Persistence of past password hashes, backing the no-reuse rule.
 *
 * <p>Only hashes are kept, and only as many as the policy needs. Implementations should prune
 * beyond that window: an unbounded history is a growing pile of offline-crackable material for
 * no added protection.
 */
public interface PasswordHistoryStore {

    /**
     * @param limit how many of the most recent hashes to return, newest first
     */
    List<String> findRecentHashes(AuthUserId userId, int limit);

    void append(AuthUserId userId, String passwordHash, Instant setAt);

    void deleteByUserId(AuthUserId userId);
}
