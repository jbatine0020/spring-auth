package io.github.springauth.core.error;

import java.time.Duration;
import java.util.Objects;

/**
 * The caller exceeded the per-IP quota of an authentication endpoint.
 *
 * <p>Carries the retry delay so the web layer can emit a {@code Retry-After} header
 * (RFC 6585 §4).
 */
public class RateLimitedException extends AuthException {

    private final Duration retryAfter;

    public RateLimitedException(Duration retryAfter) {
        super(AuthErrorCodes.RATE_LIMITED,
                "Trop de tentatives, réessayez dans "
                        + Math.max(1, Objects.requireNonNull(retryAfter, "retryAfter is required").toSeconds())
                        + " secondes");
        this.retryAfter = retryAfter;
    }

    public Duration getRetryAfter() {
        return retryAfter;
    }

    /** Seconds to advertise in the {@code Retry-After} header, never below 1. */
    public long getRetryAfterSeconds() {
        return Math.max(1, retryAfter.toSeconds());
    }
}
