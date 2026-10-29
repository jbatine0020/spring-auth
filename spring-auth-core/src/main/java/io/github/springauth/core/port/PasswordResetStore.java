package io.github.springauth.core.port;

import java.time.Instant;
import java.util.Optional;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.PasswordResetRequest;

/** Persistence of pending password-reset requests. */
public interface PasswordResetStore {

    Optional<PasswordResetRequest> findByTokenHash(String tokenHash);

    PasswordResetRequest save(PasswordResetRequest request);

    /**
     * Invalidates every pending request of a user.
     *
     * <p>Called when a new one is issued, so that asking twice does not leave two working links,
     * and after a successful reset.
     */
    void deleteByUserId(AuthUserId userId);

    /** Housekeeping for requests that expired without being used. */
    int deleteExpiredBefore(Instant before);
}
