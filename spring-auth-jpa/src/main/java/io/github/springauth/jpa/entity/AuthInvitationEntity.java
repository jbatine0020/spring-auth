package io.github.springauth.jpa.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.UserInvitation;

/** Row of {@code auth_invitations}. A single-use onboarding link. */
@Entity
@Table(name = "auth_invitations")
public class AuthInvitationEntity {

    @Id
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "user_id", nullable = false, length = 64)
    private String userId;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Column(name = "temporary_password_hash", length = 255)
    private String temporaryPasswordHash;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "redeemed_at")
    private Instant redeemedAt;

    protected AuthInvitationEntity() {
        // required by JPA
    }

    public static AuthInvitationEntity fromDomain(UserInvitation invitation) {
        AuthInvitationEntity entity = new AuthInvitationEntity();
        entity.applyFrom(invitation);
        return entity;
    }

    public void applyFrom(UserInvitation invitation) {
        this.id = invitation.getId();
        this.userId = invitation.getUserId().value();
        this.tokenHash = invitation.getTokenHash();
        this.temporaryPasswordHash = invitation.getTemporaryPasswordHash();
        this.createdAt = invitation.getCreatedAt();
        this.expiresAt = invitation.getExpiresAt();
        this.redeemedAt = invitation.getRedeemedAt();
    }

    public UserInvitation toDomain() {
        return UserInvitation.restore(id, AuthUserId.of(userId), tokenHash, temporaryPasswordHash,
                createdAt, expiresAt, redeemedAt);
    }

    public UUID getId() {
        return id;
    }
}
