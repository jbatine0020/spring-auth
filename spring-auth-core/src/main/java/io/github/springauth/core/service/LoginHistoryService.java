package io.github.springauth.core.service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.LoginAttempt;
import io.github.springauth.core.port.LoginHistoryStore;
import org.springframework.transaction.annotation.Transactional;

/**
 * Read access to the authentication history, plus its retention job.
 *
 * <p>Two audiences: the user, who gets a "recent activity" panel and can spot a session they do
 * not recognise, and the operator, who watches failure counts.
 */
@Transactional(readOnly = true)
public class LoginHistoryService {

    private static final int MAX_PAGE_SIZE = 200;

    private final LoginHistoryStore loginHistoryStore;
    private final Clock clock;

    public LoginHistoryService(LoginHistoryStore loginHistoryStore, Clock clock) {
        this.loginHistoryStore = loginHistoryStore;
        this.clock = clock;
    }

    /**
     * Most recent attempts, newest first.
     *
     * @param limit capped at 200 so a caller cannot pull the whole table in one request
     */
    public List<LoginAttempt> recentFor(AuthUserId userId, int limit) {
        int effective = Math.max(1, Math.min(limit, MAX_PAGE_SIZE));
        return loginHistoryStore.findRecentByUserId(userId, effective);
    }

    /** Failures over a trailing window. The signal an account is being targeted. */
    public long countRecentFailures(AuthUserId userId, Duration window) {
        return loginHistoryStore.countFailuresSince(userId, clock.instant().minus(window));
    }

    /**
     * Deletes history older than the retention window. Call it from a scheduled job: the library
     * never prunes on its own, because retention is a compliance decision.
     *
     * @return how many rows were deleted
     */
    @Transactional
    public int purgeOlderThan(Duration retention) {
        Instant cutoff = clock.instant().minus(retention);
        return loginHistoryStore.deleteBefore(cutoff);
    }
}
