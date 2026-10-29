package io.github.springauth.jpa.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Row of {@code auth_password_history}: one past password hash.
 *
 * <p>Append-only, and pruned to the configured window: keeping more hashes than the no-reuse rule
 * needs only grows the pile of offline-crackable material.
 */
@Entity
@Table(name = "auth_password_history")
public class AuthPasswordHistoryEntity {

    @Id
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "user_id", nullable = false, length = 64)
    private String userId;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(name = "set_at", nullable = false)
    private Instant setAt;

    protected AuthPasswordHistoryEntity() {
        // required by JPA
    }

    public AuthPasswordHistoryEntity(String userId, String passwordHash, Instant setAt) {
        this.id = UUID.randomUUID();
        this.userId = userId;
        this.passwordHash = passwordHash;
        this.setAt = setAt;
    }

    public UUID getId() {
        return id;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public Instant getSetAt() {
        return setAt;
    }
}
