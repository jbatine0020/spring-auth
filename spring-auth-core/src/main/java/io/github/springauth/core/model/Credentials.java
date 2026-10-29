package io.github.springauth.core.model;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A user's password material and the state around it: lock-out counters, when the password was
 * set, and whether a change is being forced.
 *
 * <p>The hash comparison itself lives in the service layer, which owns the
 * {@code PasswordEncoder}. What lives here are the invariants: a locked account cannot count
 * another failure, a successful authentication clears the counter, and every way of setting a
 * password resets both.
 */
public final class Credentials {

    private final UUID id;
    private final AuthUserId userId;
    private String passwordHash;
    private Instant passwordSetAt;
    private int failedAttempts;
    private Instant lockedUntil;
    private boolean mustChangePassword;
    private Instant updatedAt;

    private Credentials(UUID id, AuthUserId userId, String passwordHash, Instant passwordSetAt,
                        int failedAttempts, Instant lockedUntil, boolean mustChangePassword,
                        Instant updatedAt) {
        this.id = Objects.requireNonNull(id, "id is required");
        this.userId = Objects.requireNonNull(userId, "userId is required");
        this.passwordHash = requireNotBlank(passwordHash, "passwordHash");
        this.passwordSetAt = Objects.requireNonNull(passwordSetAt, "passwordSetAt is required");
        if (failedAttempts < 0) {
            throw new IllegalArgumentException("failedAttempts must be >= 0");
        }
        this.failedAttempts = failedAttempts;
        this.lockedUntil = lockedUntil;
        this.mustChangePassword = mustChangePassword;
        this.updatedAt = Objects.requireNonNull(updatedAt, "updatedAt is required");
    }

    /** First password for a user. */
    public static Credentials create(AuthUserId userId, String passwordHash,
                                     boolean mustChangePassword, Instant now) {
        return new Credentials(UUID.randomUUID(), userId, passwordHash, now, 0, null,
                mustChangePassword, now);
    }

    /** Rebuilds an instance from storage. Used by persistence adapters only. */
    public static Credentials restore(UUID id, AuthUserId userId, String passwordHash,
                                      Instant passwordSetAt, int failedAttempts, Instant lockedUntil,
                                      boolean mustChangePassword, Instant updatedAt) {
        return new Credentials(id, userId, passwordHash, passwordSetAt, failedAttempts, lockedUntil,
                mustChangePassword, updatedAt);
    }

    public boolean isLockedAt(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    /**
     * Password older than {@code maxAge}.
     *
     * @param maxAge null or zero disables expiry
     */
    public boolean isPasswordExpired(Instant now, Duration maxAge) {
        return maxAge != null && !maxAge.isZero() && passwordSetAt.plus(maxAge).isBefore(now);
    }

    /**
     * Single source of truth for the {@code must_change_password} claim: either an administrator
     * forced it, or the password aged out.
     */
    public boolean requiresPasswordChange(Instant now, Duration maxAge) {
        return mustChangePassword || isPasswordExpired(now, maxAge);
    }

    /**
     * Counts a failed password check and locks the account once the threshold is reached.
     *
     * @return true when this very call caused the lock, so the caller can raise an alert once
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

    /** Clears the failure counter after a valid password. */
    public void recordSuccessfulAuthentication(Instant now) {
        this.failedAttempts = 0;
        this.lockedUntil = null;
        this.updatedAt = now;
    }

    /** The user changes their own password: the forced-change flag is satisfied. */
    public void changePassword(String newPasswordHash, Instant now) {
        applyNewPassword(newPasswordHash, now);
        this.mustChangePassword = false;
    }

    /** An administrator sets the password: the user must change it at next login. */
    public void resetByAdministrator(String newPasswordHash, Instant now) {
        applyNewPassword(newPasswordHash, now);
        this.mustChangePassword = true;
    }

    /** Administrative unlock, before the lock expires on its own. */
    public void unlock(Instant now) {
        this.failedAttempts = 0;
        this.lockedUntil = null;
        this.updatedAt = now;
    }

    private void applyNewPassword(String newPasswordHash, Instant now) {
        this.passwordHash = requireNotBlank(newPasswordHash, "passwordHash");
        this.passwordSetAt = now;
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

    public String getPasswordHash() {
        return passwordHash;
    }

    public Instant getPasswordSetAt() {
        return passwordSetAt;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public boolean isMustChangePassword() {
        return mustChangePassword;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
