package io.github.springauth.core.spi;

import java.time.Instant;

import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.OtpChannel;

/**
 * Delivery of the secrets the library produces but cannot send itself.
 *
 * <p>Email and SMS transports differ wildly between projects, so the library stops at the point
 * where a secret exists and hands it over. Implement this against your own mailer and SMS gateway.
 *
 * <p>Two rules apply to every implementation:
 * <ul>
 *   <li>Never log the raw values. They are single-factor credentials for the duration of their
 *       window.</li>
 *   <li>Send after the surrounding transaction commits. Delivering an OTP for a request that then
 *       rolls back gives the user a code the server has never heard of.</li>
 * </ul>
 *
 * <p>The default methods do nothing, so an application can implement only what it uses. A
 * deployment that leaves {@link #sendPasswordResetOtp} unimplemented while password reset is
 * enabled will simply never deliver codes. The starter logs a warning at boot in that case.
 */
public interface AuthMessenger {

    /** Delivers a login code after the password has been validated. */
    default void sendLoginOtp(AuthUser user, OtpChannel channel, String rawCode, Instant expiresAt) {
        // no-op by default
    }

    /**
     * Sends the reset link and, when the deployment requires it, the numeric code.
     *
     * @param user      the account being reset
     * @param rawToken  raw link token, put it in the URL you send by email
     * @param rawOtp    raw numeric code to send by SMS, null when the deployment is link-only
     * @param expiresAt when both stop working
     */
    default void sendPasswordResetOtp(AuthUser user, String rawToken, String rawOtp, Instant expiresAt) {
        // no-op by default
    }

    /**
     * Sends the invitation link.
     *
     * @param rawToken raw invitation token, put it in the activation URL
     */
    default void sendInvitation(AuthUser user, String rawToken, Instant expiresAt) {
        // no-op by default
    }

    /**
     * Warns the account owner that their account just locked after repeated failures.
     *
     * <p>Worth wiring: it is often the first signal a user gets that someone is trying their
     * password.
     */
    default void sendAccountLockedAlert(AuthUser user, Instant lockedUntil) {
        // no-op by default
    }

    /** Confirms a password change to its owner, so an unexpected one gets reported. */
    default void sendPasswordChangedNotice(AuthUser user, Instant changedAt) {
        // no-op by default
    }
}
