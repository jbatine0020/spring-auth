package io.github.springauth.core.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

import io.github.springauth.core.error.PasswordException;

/**
 * A pending "forgot my password" request, carrying two independent factors.
 *
 * <p>The emailed link holds a 256-bit token; only its digest is stored. The SMS code is a short
 * numeric OTP stored as a slow hash. Requiring both means neither a compromised mailbox nor a
 * hijacked phone is sufficient on its own.
 *
 * <p>The request is single-use and locks after a few wrong OTP attempts, which is what keeps a
 * six-digit code out of reach of a brute-force sweep.
 */
public final class PasswordResetRequest {

    private final UUID id;
    private final AuthUserId userId;
    private final String tokenHash;
    private final String otpHash;
    private final Instant createdAt;
    private final Instant expiresAt;
    private final String requestedBy;
    private Instant usedAt;
    private int failedAttempts;
    private Instant lockedAt;

    private PasswordResetRequest(UUID id, AuthUserId userId, String tokenHash, String otpHash,
                                 Instant createdAt, Instant expiresAt, Instant usedAt,
                                 int failedAttempts, Instant lockedAt, String requestedBy) {
        this.id = Objects.requireNonNull(id, "id is required");
        this.userId = Objects.requireNonNull(userId, "userId is required");
        this.tokenHash = requireNotBlank(tokenHash, "tokenHash");
        this.otpHash = otpHash;
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt is required");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt is required");
        if (!expiresAt.isAfter(createdAt)) {
            throw new IllegalArgumentException("expiresAt must be strictly after createdAt");
        }
        if (failedAttempts < 0) {
            throw new IllegalArgumentException("failedAttempts must be >= 0");
        }
        this.usedAt = usedAt;
        this.failedAttempts = failedAttempts;
        this.lockedAt = lockedAt;
        this.requestedBy = requestedBy;
    }

    /**
     * @param otpHash hash of the SMS code, null when the deployment runs link-only
     * @param requestedBy who triggered it: the user themselves, or an administrator id
     */
    public static PasswordResetRequest issue(AuthUserId userId, String tokenHash, String otpHash,
                                             Instant createdAt, Instant expiresAt, String requestedBy) {
        return new PasswordResetRequest(UUID.randomUUID(), userId, tokenHash, otpHash,
                createdAt, expiresAt, null, 0, null, requestedBy);
    }

    /** Rebuilds an instance from storage. Used by persistence adapters only. */
    public static PasswordResetRequest restore(UUID id, AuthUserId userId, String tokenHash,
                                               String otpHash, Instant createdAt, Instant expiresAt,
                                               Instant usedAt, int failedAttempts, Instant lockedAt,
                                               String requestedBy) {
        return new PasswordResetRequest(id, userId, tokenHash, otpHash, createdAt, expiresAt,
                usedAt, failedAttempts, lockedAt, requestedBy);
    }

    /**
     * Consumes the request.
     *
     * @throws PasswordException when it was already used, is locked, or has expired
     */
    public void consume(Instant at) {
        if (usedAt != null) {
            throw PasswordException.resetAlreadyUsed();
        }
        if (isLocked()) {
            throw PasswordException.resetLocked();
        }
        if (isExpiredAt(at)) {
            throw PasswordException.resetExpired();
        }
        this.usedAt = at;
    }

    /** Counts a wrong OTP and locks the request once the allowance runs out. */
    public void recordFailedAttempt(int maxAttempts, Instant at) {
        if (isLocked()) {
            return;
        }
        this.failedAttempts += 1;
        if (this.failedAttempts >= maxAttempts) {
            this.lockedAt = at;
        }
    }

    public boolean isUsed() {
        return usedAt != null;
    }

    public boolean isLocked() {
        return lockedAt != null;
    }

    public boolean isExpiredAt(Instant at) {
        return at.isAfter(expiresAt);
    }

    /** True when this deployment requires an OTP alongside the link. */
    public boolean requiresOtp() {
        return otpHash != null && !otpHash.isBlank();
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

    public String getTokenHash() {
        return tokenHash;
    }

    public String getOtpHash() {
        return otpHash;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getUsedAt() {
        return usedAt;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public Instant getLockedAt() {
        return lockedAt;
    }

    public String getRequestedBy() {
        return requestedBy;
    }
}
