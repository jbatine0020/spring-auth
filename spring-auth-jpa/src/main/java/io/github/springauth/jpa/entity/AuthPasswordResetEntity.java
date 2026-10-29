package io.github.springauth.jpa.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.PasswordResetRequest;

/** Row of {@code auth_password_resets}. One pending forgotten-password request. */
@Entity
@Table(name = "auth_password_resets")
public class AuthPasswordResetEntity {

    @Id
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "user_id", nullable = false, length = 64)
    private String userId;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    /** Null when the deployment sends the link without a second factor. */
    @Column(name = "otp_hash", length = 255)
    private String otpHash;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;

    @Column(name = "locked_at")
    private Instant lockedAt;

    @Column(name = "requested_by", length = 64)
    private String requestedBy;

    protected AuthPasswordResetEntity() {
        // required by JPA
    }

    public static AuthPasswordResetEntity fromDomain(PasswordResetRequest request) {
        AuthPasswordResetEntity entity = new AuthPasswordResetEntity();
        entity.applyFrom(request);
        return entity;
    }

    public void applyFrom(PasswordResetRequest request) {
        this.id = request.getId();
        this.userId = request.getUserId().value();
        this.tokenHash = request.getTokenHash();
        this.otpHash = request.getOtpHash();
        this.createdAt = request.getCreatedAt();
        this.expiresAt = request.getExpiresAt();
        this.usedAt = request.getUsedAt();
        this.failedAttempts = request.getFailedAttempts();
        this.lockedAt = request.getLockedAt();
        this.requestedBy = request.getRequestedBy();
    }

    public PasswordResetRequest toDomain() {
        return PasswordResetRequest.restore(id, AuthUserId.of(userId), tokenHash, otpHash,
                createdAt, expiresAt, usedAt, failedAttempts, lockedAt, requestedBy);
    }

    public UUID getId() {
        return id;
    }
}
