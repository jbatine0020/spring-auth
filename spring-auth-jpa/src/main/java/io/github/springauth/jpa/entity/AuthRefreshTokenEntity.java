package io.github.springauth.jpa.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.RefreshToken;

/**
 * Row of {@code auth_refresh_tokens}.
 *
 * <p>Revoked rows are kept, not deleted: replay detection depends on still finding the token that
 * was already rotated. Housekeeping removes them once they expire, well after they stop being
 * evidence.
 */
@Entity
@Table(name = "auth_refresh_tokens")
public class AuthRefreshTokenEntity {

    @Id
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "user_id", nullable = false, length = 64)
    private String userId;

    @Column(name = "family_id", nullable = false)
    private UUID familyId;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "replaced_by")
    private UUID replacedBy;

    protected AuthRefreshTokenEntity() {
        // required by JPA
    }

    public static AuthRefreshTokenEntity fromDomain(RefreshToken token) {
        AuthRefreshTokenEntity entity = new AuthRefreshTokenEntity();
        entity.applyFrom(token);
        return entity;
    }

    public void applyFrom(RefreshToken token) {
        this.id = token.getId();
        this.userId = token.getUserId().value();
        this.familyId = token.getFamilyId();
        this.tokenHash = token.getTokenHash();
        this.issuedAt = token.getIssuedAt();
        this.expiresAt = token.getExpiresAt();
        this.revokedAt = token.getRevokedAt();
        this.replacedBy = token.getReplacedBy();
    }

    public RefreshToken toDomain() {
        return RefreshToken.restore(id, AuthUserId.of(userId), familyId, tokenHash,
                issuedAt, expiresAt, revokedAt, replacedBy);
    }

    public UUID getId() {
        return id;
    }
}
