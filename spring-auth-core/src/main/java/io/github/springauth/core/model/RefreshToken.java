package io.github.springauth.core.model;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A rotating refresh token (RFC 6749, hardened per RFC 6819 §5.2.2.3).
 *
 * <p>Only the SHA-256 digest is persisted; the raw secret is handed to the client once and never
 * stored. Every refresh mints a new token and revokes the one presented, so a stolen token is
 * only useful until the legitimate client refreshes.
 *
 * <p>All tokens descending from one login share a <b>family</b> id. Presenting an already-revoked
 * token means two parties hold the same secret, so the whole family is invalidated: attacker and
 * victim are both logged out and the theft surfaces immediately instead of persisting silently.
 */
public final class RefreshToken {

    private final UUID id;
    private final AuthUserId userId;
    private final UUID familyId;
    private final String tokenHash;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private Instant revokedAt;
    private UUID replacedBy;

    private RefreshToken(UUID id, AuthUserId userId, UUID familyId, String tokenHash,
                         Instant issuedAt, Instant expiresAt, Instant revokedAt, UUID replacedBy) {
        this.id = Objects.requireNonNull(id, "id is required");
        this.userId = Objects.requireNonNull(userId, "userId is required");
        this.familyId = Objects.requireNonNull(familyId, "familyId is required");
        this.tokenHash = requireNotBlank(tokenHash, "tokenHash");
        this.issuedAt = Objects.requireNonNull(issuedAt, "issuedAt is required");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt is required");
        this.revokedAt = revokedAt;
        this.replacedBy = replacedBy;
    }

    /** New login: opens a fresh family. */
    public static RefreshToken issueNewSession(AuthUserId userId, String tokenHash,
                                               Duration ttl, Instant now) {
        return new RefreshToken(UUID.randomUUID(), userId, UUID.randomUUID(), tokenHash,
                now, now.plus(ttl), null, null);
    }

    /** Refresh: stays within the family of the token being rotated. */
    public static RefreshToken issueWithinFamily(AuthUserId userId, UUID familyId, String tokenHash,
                                                 Duration ttl, Instant now) {
        return new RefreshToken(UUID.randomUUID(), userId, familyId, tokenHash,
                now, now.plus(ttl), null, null);
    }

    /** Rebuilds an instance from storage. Used by persistence adapters only. */
    public static RefreshToken restore(UUID id, AuthUserId userId, UUID familyId, String tokenHash,
                                       Instant issuedAt, Instant expiresAt, Instant revokedAt,
                                       UUID replacedBy) {
        return new RefreshToken(id, userId, familyId, tokenHash, issuedAt, expiresAt,
                revokedAt, replacedBy);
    }

    public boolean isActiveAt(Instant now) {
        return revokedAt == null && now.isBefore(expiresAt);
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpiredAt(Instant now) {
        return !now.isBefore(expiresAt);
    }

    /** Revokes this token and links it to its successor, forming the audit chain of the family. */
    public void rotateTo(UUID successorId, Instant now) {
        if (revokedAt != null) {
            throw new IllegalStateException("Refresh token already revoked");
        }
        this.revokedAt = now;
        this.replacedBy = Objects.requireNonNull(successorId, "successorId is required");
    }

    /** Idempotent revocation, used on logout and on family invalidation. */
    public void revoke(Instant now) {
        if (revokedAt == null) {
            this.revokedAt = now;
        }
    }

    private static String requireNotBlank(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }

    public UUID getId() {
        return id;
    }

    public AuthUserId getUserId() {
        return userId;
    }

    public UUID getFamilyId() {
        return familyId;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public UUID getReplacedBy() {
        return replacedBy;
    }
}
