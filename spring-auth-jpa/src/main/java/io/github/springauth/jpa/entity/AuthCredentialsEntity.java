package io.github.springauth.jpa.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.Credentials;

/**
 * Row of {@code auth_credentials}, one per user.
 *
 * <p>Mapping is explicit in both directions rather than through field access on the domain type:
 * the aggregate keeps its invariants and its private constructor, and the schema can evolve
 * without leaking into it.
 */
@Entity
@Table(name = "auth_credentials")
public class AuthCredentialsEntity {

    @Id
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "user_id", nullable = false, unique = true, length = 64)
    private String userId;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(name = "password_set_at", nullable = false)
    private Instant passwordSetAt;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "must_change_password", nullable = false)
    private boolean mustChangePassword;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected AuthCredentialsEntity() {
        // required by JPA
    }

    public static AuthCredentialsEntity fromDomain(Credentials credentials) {
        AuthCredentialsEntity entity = new AuthCredentialsEntity();
        entity.applyFrom(credentials);
        return entity;
    }

    /** Copies the aggregate state onto an already-managed row. */
    public void applyFrom(Credentials credentials) {
        this.id = credentials.getId();
        this.userId = credentials.getUserId().value();
        this.passwordHash = credentials.getPasswordHash();
        this.passwordSetAt = credentials.getPasswordSetAt();
        this.failedAttempts = credentials.getFailedAttempts();
        this.lockedUntil = credentials.getLockedUntil();
        this.mustChangePassword = credentials.isMustChangePassword();
        this.updatedAt = credentials.getUpdatedAt();
    }

    public Credentials toDomain() {
        return Credentials.restore(id, AuthUserId.of(userId), passwordHash, passwordSetAt,
                failedAttempts, lockedUntil, mustChangePassword, updatedAt);
    }

    public UUID getId() {
        return id;
    }

    public String getUserId() {
        return userId;
    }
}
