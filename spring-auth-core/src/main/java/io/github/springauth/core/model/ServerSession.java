package io.github.springauth.core.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Server-side session metadata. No password, OTP or bearer token is stored here. */
public record ServerSession(UUID id, AuthUserId userId, Instant createdAt, Instant lastAccessAt,
                            Instant absoluteExpiresAt, boolean revoked) {

    public ServerSession {
        Objects.requireNonNull(id, "id is required");
        Objects.requireNonNull(userId, "userId is required");
        Objects.requireNonNull(createdAt, "createdAt is required");
        Objects.requireNonNull(lastAccessAt, "lastAccessAt is required");
        Objects.requireNonNull(absoluteExpiresAt, "absoluteExpiresAt is required");
    }

    public boolean isActiveAt(Instant now, java.time.Duration inactivityTimeout) {
        return !revoked && now.isBefore(absoluteExpiresAt)
                && now.isBefore(lastAccessAt.plus(inactivityTimeout));
    }

    public ServerSession touchedAt(Instant now) {
        return new ServerSession(id, userId, createdAt, now, absoluteExpiresAt, revoked);
    }

    public ServerSession asRevoked() {
        return new ServerSession(id, userId, createdAt, lastAccessAt, absoluteExpiresAt, true);
    }
}
