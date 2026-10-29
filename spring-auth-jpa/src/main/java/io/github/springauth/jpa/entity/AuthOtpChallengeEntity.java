package io.github.springauth.jpa.entity;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.OtpChallenge;
import io.github.springauth.core.model.OtpChannel;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** One mutable challenge row per user and channel; it contains only a BCrypt hash. */
@Entity
@Table(name = "auth_otp_challenges")
public class AuthOtpChallengeEntity {
    @Id private UUID id;
    @Column(name = "user_id", nullable = false, length = 64) private String userId;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 8) private OtpChannel channel;
    @Column(name = "code_hash", nullable = false, length = 255) private String codeHash;
    @Column(name = "destination_fingerprint", nullable = false, length = 64) private String destinationFingerprint;
    @Column(name = "destination_masked", nullable = false, length = 320) private String destinationMasked;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "expires_at", nullable = false) private Instant expiresAt;
    @Column(name = "consumed_at") private Instant consumedAt;
    @Column(name = "failed_attempts", nullable = false) private int failedAttempts;
    @Column(name = "locked_at") private Instant lockedAt;
    @Column(name = "last_sent_at", nullable = false) private Instant lastSentAt;
    protected AuthOtpChallengeEntity() { }
    public static AuthOtpChallengeEntity from(OtpChallenge source) { var entity = new AuthOtpChallengeEntity(); entity.apply(source); return entity; }
    public void apply(OtpChallenge source) { id=source.id(); userId=source.userId().value(); channel=source.channel(); codeHash=source.codeHash(); destinationFingerprint=source.destinationFingerprint(); destinationMasked=source.destinationMasked(); createdAt=source.createdAt(); expiresAt=source.expiresAt(); consumedAt=source.consumedAt(); failedAttempts=source.failedAttempts(); lockedAt=source.lockedAt(); lastSentAt=source.lastSentAt(); }
    public OtpChallenge toDomain() { return OtpChallenge.restore(id, AuthUserId.of(userId), channel, codeHash, destinationFingerprint, destinationMasked, createdAt, expiresAt, consumedAt, failedAttempts, lockedAt, lastSentAt); }
}
