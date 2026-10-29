package io.github.springauth.jpa.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.MfaCredential;

/**
 * Row of {@code auth_mfa_credentials}, one per user.
 *
 * <p>{@code encrypted_secret} holds the AES-GCM ciphertext of the TOTP seed, never the seed
 * itself, so a database dump does not hand over everyone's second factor.
 */
@Entity
@Table(name = "auth_mfa_credentials")
public class AuthMfaCredentialEntity {

    @Id
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "user_id", nullable = false, unique = true, length = 64)
    private String userId;

    @Column(name = "encrypted_secret", nullable = false, length = 512)
    private String encryptedSecret;

    @Column(name = "last_accepted_counter", nullable = false)
    private long lastAcceptedCounter;

    @Column(name = "confirmed_at")
    private Instant confirmedAt;

    @Column(name = "reset_requested_at")
    private Instant resetRequestedAt;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected AuthMfaCredentialEntity() {
        // required by JPA
    }

    public static AuthMfaCredentialEntity fromDomain(MfaCredential credential) {
        AuthMfaCredentialEntity entity = new AuthMfaCredentialEntity();
        entity.applyFrom(credential);
        return entity;
    }

    public void applyFrom(MfaCredential credential) {
        this.id = credential.getId();
        this.userId = credential.getUserId().value();
        this.encryptedSecret = credential.getEncryptedSecret();
        this.lastAcceptedCounter = credential.getLastAcceptedCounter();
        this.confirmedAt = credential.getConfirmedAt();
        this.resetRequestedAt = credential.getResetRequestedAt();
        this.failedAttempts = credential.getFailedAttempts();
        this.lockedUntil = credential.getLockedUntil();
        this.createdAt = credential.getCreatedAt();
        this.updatedAt = credential.getUpdatedAt();
    }

    public MfaCredential toDomain() {
        return MfaCredential.restore(id, AuthUserId.of(userId), encryptedSecret, lastAcceptedCounter,
                confirmedAt, resetRequestedAt, failedAttempts, lockedUntil, createdAt, updatedAt);
    }

    public UUID getId() {
        return id;
    }
}
