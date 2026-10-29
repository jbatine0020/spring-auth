package io.github.springauth.core.error;

/** Raised when a login OTP resend is requested before its cooldown has elapsed. */
public final class OtpResendCooldownException extends RuntimeException {
    private final long retryAfterSeconds;

    public OtpResendCooldownException(long retryAfterSeconds) {
        super("OTP resend is not available yet");
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long getRetryAfterSeconds() { return retryAfterSeconds; }
}
