package io.github.springauth.core.service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import io.github.springauth.core.error.SessionUnavailableException;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.ServerSession;
import io.github.springauth.core.port.ServerSessionStore;

/** Coordinates idle timeout, absolute timeout and revocation for server-side sessions. */
public final class ServerSessionService {

    private final ServerSessionStore store;
    private final Clock clock;
    private final Duration inactivityTimeout;
    private final Duration absoluteTimeout;

    public ServerSessionService(ServerSessionStore store, Clock clock, Duration inactivityTimeout,
                                Duration absoluteTimeout) {
        if (inactivityTimeout.isNegative() || inactivityTimeout.isZero()
                || absoluteTimeout.isNegative() || absoluteTimeout.isZero()) {
            throw new IllegalArgumentException("session timeouts must be positive");
        }
        this.store = store;
        this.clock = clock;
        this.inactivityTimeout = inactivityTimeout;
        this.absoluteTimeout = absoluteTimeout;
    }

    public ServerSession open(AuthUserId userId) {
        try {
            Instant now = clock.instant();
            return store.create(userId, now, now.plus(absoluteTimeout));
        } catch (RuntimeException ex) {
            throw new SessionUnavailableException("session backend unavailable", ex);
        }
    }

    public ServerSession requireActive(UUID sessionId) {
        try {
            ServerSession session = store.find(sessionId).orElseThrow(
                    () -> new SessionUnavailableException("session is not active", null));
            Instant now = clock.instant();
            if (!session.isActiveAt(now, inactivityTimeout)) {
                if (!session.revoked()) store.save(session.asRevoked());
                throw new SessionUnavailableException("session is not active", null);
            }
            return store.save(session.touchedAt(now));
        } catch (SessionUnavailableException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            throw new SessionUnavailableException("session backend unavailable", ex);
        }
    }

    public void revoke(UUID sessionId) {
        try {
            store.find(sessionId).ifPresent(session -> store.save(session.asRevoked()));
        } catch (RuntimeException ex) {
            throw new SessionUnavailableException("session backend unavailable", ex);
        }
    }

    public int revokeAllForUser(AuthUserId userId) {
        try {
            return store.revokeAllForUser(userId, clock.instant());
        } catch (RuntimeException ex) {
            throw new SessionUnavailableException("session backend unavailable", ex);
        }
    }
}
