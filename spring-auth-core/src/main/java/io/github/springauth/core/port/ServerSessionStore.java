package io.github.springauth.core.port;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.ServerSession;

/** Server-side session persistence port. Implementations must fail closed on backend errors. */
public interface ServerSessionStore {

    ServerSession create(AuthUserId userId, Instant now, Instant absoluteExpiresAt);

    Optional<ServerSession> find(UUID sessionId);

    ServerSession save(ServerSession session);

    /** Revokes every active server session belonging to the user. */
    int revokeAllForUser(AuthUserId userId, Instant now);
}
