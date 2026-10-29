package io.github.springauth.core.model;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Persisted, single-use login code. The raw code is never retained here. */
public final class OtpChallenge {

    private final UUID id;
    private final AuthUserId userId;
    private final OtpChannel channel;
    private final String codeHash;
    private final String destinationFingerprint;
    private final String destinationMasked;
    private final Instant createdAt;
    private final Instant expiresAt;
    private Instant consumedAt;
    private int failedAttempts;
    private Instant lockedAt;
    private Instant lastSentAt;

    private OtpChallenge(UUID id, AuthUserId userId, OtpChannel channel, String codeHash,
                         String destinationFingerprint, String destinationMasked, Instant createdAt,
                         Instant expiresAt, Instant consumedAt, int failedAttempts, Instant lockedAt,
                         Instant lastSentAt) {
        this.id = Objects.requireNonNull(id);
        this.userId = Objects.requireNonNull(userId);
        this.channel = Objects.requireNonNull(channel);
        this.codeHash = Objects.requireNonNull(codeHash);
        this.destinationFingerprint = Objects.requireNonNull(destinationFingerprint);
        this.destinationMasked = Objects.requireNonNull(destinationMasked);
        this.createdAt = Objects.requireNonNull(createdAt);
        this.expiresAt = Objects.requireNonNull(expiresAt);
        this.consumedAt = consumedAt;
        this.failedAttempts = failedAttempts;
        this.lockedAt = lockedAt;
        this.lastSentAt = Objects.requireNonNull(lastSentAt);
    }

    public static OtpChallenge issue(AuthUserId userId, OtpChannel channel, String codeHash,
                                     String destinationFingerprint, String destinationMasked,
                                     Instant now, Duration ttl) {
        return new OtpChallenge(UUID.randomUUID(), userId, channel, codeHash, destinationFingerprint,
                destinationMasked, now, now.plus(ttl), null, 0, null, now);
    }

    /** Replaces every secret-bearing value while retaining the locked row for concurrency safety. */
    public static OtpChallenge reissue(OtpChallenge previous, String codeHash,
                                       String destinationFingerprint, String destinationMasked,
                                       Instant now, Duration ttl) {
        return new OtpChallenge(previous.id, previous.userId, previous.channel, codeHash,
                destinationFingerprint, destinationMasked, now, now.plus(ttl), null, 0, null, now);
    }

    public static OtpChallenge restore(UUID id, AuthUserId userId, OtpChannel channel, String codeHash,
                                       String destinationFingerprint, String destinationMasked,
                                       Instant createdAt, Instant expiresAt, Instant consumedAt,
                                       int failedAttempts, Instant lockedAt, Instant lastSentAt) {
        return new OtpChallenge(id, userId, channel, codeHash, destinationFingerprint, destinationMasked,
                createdAt, expiresAt, consumedAt, failedAttempts, lockedAt, lastSentAt);
    }

    public boolean canVerifyAt(Instant now) {
        return consumedAt == null && !expiresAt.isBefore(now) && lockedAt == null;
    }

    public boolean canResendAt(Instant now, Duration cooldown) {
        return canVerifyAt(now) && !lastSentAt.plus(cooldown).isAfter(now);
    }

    public void consume(Instant now) { consumedAt = now; }

    public void recordInvalidAttempt(int maxAttempts, Instant now) {
        failedAttempts++;
        if (failedAttempts >= maxAttempts) {
            lockedAt = now;
        }
    }

    public UUID id() { return id; }
    public AuthUserId userId() { return userId; }
    public OtpChannel channel() { return channel; }
    public String codeHash() { return codeHash; }
    public String destinationFingerprint() { return destinationFingerprint; }
    public String destinationMasked() { return destinationMasked; }
    public Instant createdAt() { return createdAt; }
    public Instant expiresAt() { return expiresAt; }
    public Instant consumedAt() { return consumedAt; }
    public int failedAttempts() { return failedAttempts; }
    public Instant lockedAt() { return lockedAt; }
    public Instant lastSentAt() { return lastSentAt; }
}
