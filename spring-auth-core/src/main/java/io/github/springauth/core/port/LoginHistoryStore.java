package io.github.springauth.core.port;

import java.time.Instant;
import java.util.List;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.LoginAttempt;

/** Persistence of authentication attempts. */
public interface LoginHistoryStore {

    void append(LoginAttempt attempt);

    /**
     * Most recent attempts of a user, newest first. Feeds the "recent activity" panel users see
     * in their security settings.
     */
    List<LoginAttempt> findRecentByUserId(AuthUserId userId, int limit);

    /** Counts failures since an instant. Useful for alerting on a spike. */
    long countFailuresSince(AuthUserId userId, Instant since);

    /** Counts successful connections since an instant, for operational dashboards. */
    default long countSuccessfulSince(Instant since) { return 0; }

    /** Housekeeping: history grows fast, prune it on a retention schedule. */
    int deleteBefore(Instant before);
}
