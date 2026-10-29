package io.github.springauth.core.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A single-use invitation link used to onboard a user.
 *
 * <p>The link carries a 256-bit token whose digest alone is stored, so the token itself is the
 * credential: whoever holds it can activate the account, which is why it expires and cannot be
 * redeemed twice. An optional temporary password hash lets the invitation double as the initial
 * credential for flows where the user does not choose their own password.
 */
public final class UserInvitation {

    private final UUID id;
    private final AuthUserId userId;
    private final String tokenHash;
    private final String temporaryPasswordHash;
    private final Instant createdAt;
    private final Instant expiresAt;
    private Instant redeemedAt;

    private UserInvitation(UUID id, AuthUserId userId, String tokenHash, String temporaryPasswordHash,
                           Instant createdAt, Instant expiresAt, Instant redeemedAt) {
        this.id = Objects.requireNonNull(id, "id is required");
        this.userId = Objects.requireNonNull(userId, "userId is required");
        this.tokenHash = requireNotBlank(tokenHash, "tokenHash");
        this.temporaryPasswordHash = temporaryPasswordHash;
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt is required");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt is required");
        if (!expiresAt.isAfter(createdAt)) {
            throw new IllegalArgumentException("expiresAt must be strictly after createdAt");
        }
        this.redeemedAt = redeemedAt;
    }

    public static UserInvitation issue(AuthUserId userId, String tokenHash, String temporaryPasswordHash,
                                       Instant createdAt, Instant expiresAt) {
        return new UserInvitation(UUID.randomUUID(), userId, tokenHash, temporaryPasswordHash,
                createdAt, expiresAt, null);
    }

    /** Rebuilds an instance from storage. Used by persistence adapters only. */
    public static UserInvitation restore(UUID id, AuthUserId userId, String tokenHash,
                                         String temporaryPasswordHash, Instant createdAt,
                                         Instant expiresAt, Instant redeemedAt) {
        return new UserInvitation(id, userId, tokenHash, temporaryPasswordHash, createdAt,
                expiresAt, redeemedAt);
    }

    public boolean isRedeemable(Instant at) {
        return redeemedAt == null && !at.isAfter(expiresAt);
    }

    /** Marks the invitation as consumed. Callers check {@link #isRedeemable} first. */
    public void redeem(Instant at) {
        if (!isRedeemable(at)) {
            throw new IllegalStateException("Invitation is not redeemable");
        }
        this.redeemedAt = at;
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

    public String getTokenHash() {
        return tokenHash;
    }

    public String getTemporaryPasswordHash() {
        return temporaryPasswordHash;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getRedeemedAt() {
        return redeemedAt;
    }
}
