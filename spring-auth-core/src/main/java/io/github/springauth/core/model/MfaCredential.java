package io.github.springauth.core.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

import io.github.springauth.core.crypto.TotpGenerator;

/**
 * A user's TOTP factor: the encrypted seed plus everything needed to make it safe to use.
 *
 * <p>Three states of the lifecycle matter:
 * <ol>
 *   <li><b>enrolled</b>: a seed exists but no code has ever been validated. The factor does not
 *       count yet, which is what prevents a half-finished enrolment from locking the user out.</li>
 *   <li><b>confirmed</b>: a first valid code was submitted; {@code confirmedAt} is set and the
 *       factor is now required at every login.</li>
 *   <li><b>reset</b>: an administrator rotated the seed, so the user has to enrol again.</li>
 * </ol>
 *
 * <p>{@code lastAcceptedCounter} is the replay guard: a TOTP code stays valid for its whole
 * 30-second step, so without it an observed code could be reused. Lock-out is tracked per account
 * rather than per IP, because an attacker holding a challenge token can spread guesses across
 * many addresses.
 */
public final class MfaCredential {

    private final UUID id;
    private final AuthUserId userId;
    private String encryptedSecret;
    private long lastAcceptedCounter;
    private Instant confirmedAt;
    private Instant resetRequestedAt;
    private int failedAttempts;
    private Instant lockedUntil;
    private final Instant createdAt;
    private Instant updatedAt;

    private MfaCredential(UUID id, AuthUserId userId, String encryptedSecret, long lastAcceptedCounter,
                          Instant confirmedAt, Instant resetRequestedAt, int failedAttempts,
                          Instant lockedUntil, Instant createdAt, Instant updatedAt) {
        this.id = Objects.requireNonNull(id, "id is required");
        this.userId = Objects.requireNonNull(userId, "userId is required");
        this.encryptedSecret = requireNotBlank(encryptedSecret, "encryptedSecret");
        this.lastAcceptedCounter = lastAcceptedCounter;
        this.confirmedAt = confirmedAt;
        this.resetRequestedAt = resetRequestedAt;
        if (failedAttempts < 0) {
            throw new IllegalArgumentException("failedAttempts must be >= 0");
        }
        this.failedAttempts = failedAttempts;
        this.lockedUntil = lockedUntil;
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt is required");
        this.updatedAt = Objects.requireNonNull(updatedAt, "updatedAt is required");
    }

    /** Starts an enrolment: the seed is stored encrypted, nothing is confirmed yet. */
    public static MfaCredential enroll(AuthUserId userId, String encryptedSecret, Instant now) {
        return new MfaCredential(UUID.randomUUID(), userId, encryptedSecret,
                TotpGenerator.NEVER_USED, null, null, 0, null, now, now);
    }

    /** Rebuilds an instance from storage. Used by persistence adapters only. */
    public static MfaCredential restore(UUID id, AuthUserId userId, String encryptedSecret,
                                        long lastAcceptedCounter, Instant confirmedAt,
                                        Instant resetRequestedAt, int failedAttempts,
                                        Instant lockedUntil, Instant createdAt, Instant updatedAt) {
        return new MfaCredential(id, userId, encryptedSecret, lastAcceptedCounter, confirmedAt,
                resetRequestedAt, failedAttempts, lockedUntil, createdAt, updatedAt);
    }

    public boolean isConfirmed() {
        return confirmedAt != null;
    }

    public boolean isLockedAt(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    /** Enrolment state as seen by the login flow. */
    public MfaStatus status() {
        if (confirmedAt != null) {
            return MfaStatus.CONFIGURED;
        }
        return resetRequestedAt != null ? MfaStatus.RESET_PENDING : MfaStatus.NOT_CONFIGURED;
    }

    /**
     * Counts an invalid code and locks verification once the threshold is reached.
     *
     * @return true when this call caused the lock
     */
    public boolean recordFailedAttempt(LockoutPolicy policy, Instant now) {
        if (isLockedAt(now)) {
            return false;
        }
        this.failedAttempts += 1;
        this.updatedAt = now;
        if (this.failedAttempts >= policy.maxAttempts()) {
            this.lockedUntil = now.plus(policy.duration());
            return true;
        }
        return false;
    }

    /**
     * Records a valid code: stores its counter, confirms the factor on first success, and clears
     * any lock-out.
     *
     * @throws IllegalStateException when the counter is not strictly newer than the last accepted
     *                               one. The caller must have verified the code first
     */
    public void recordSuccessfulVerification(long counter, Instant now) {
        if (counter <= lastAcceptedCounter) {
            throw new IllegalStateException("TOTP counter " + counter
                    + " is not newer than the last accepted counter " + lastAcceptedCounter);
        }
        this.lastAcceptedCounter = counter;
        this.failedAttempts = 0;
        this.lockedUntil = null;
        this.resetRequestedAt = null;
        if (this.confirmedAt == null) {
            this.confirmedAt = now;
        }
        this.updatedAt = now;
    }

    /**
     * Administrative reset: a brand-new seed, unconfirmed, with the replay counter rewound.
     * The user must enrol again before authenticating.
     */
    public void rotateSecret(String newEncryptedSecret, Instant now) {
        this.encryptedSecret = requireNotBlank(newEncryptedSecret, "encryptedSecret");
        this.lastAcceptedCounter = TotpGenerator.NEVER_USED;
        this.confirmedAt = null;
        this.resetRequestedAt = now;
        this.failedAttempts = 0;
        this.lockedUntil = null;
        this.updatedAt = now;
    }

    /** Re-enrolment by the user themselves: new seed, no reset marker. */
    public void replaceSecret(String newEncryptedSecret, Instant now) {
        this.encryptedSecret = requireNotBlank(newEncryptedSecret, "encryptedSecret");
        this.lastAcceptedCounter = TotpGenerator.NEVER_USED;
        this.confirmedAt = null;
        this.resetRequestedAt = null;
        this.failedAttempts = 0;
        this.lockedUntil = null;
        this.updatedAt = now;
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

    public String getEncryptedSecret() {
        return encryptedSecret;
    }

    public long getLastAcceptedCounter() {
        return lastAcceptedCounter;
    }

    public Instant getConfirmedAt() {
        return confirmedAt;
    }

    public Instant getResetRequestedAt() {
        return resetRequestedAt;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
