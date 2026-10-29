package io.github.springauth.core.service;

import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.OtpChannel;

/** Result of external authentication before token/session issuance. */
public record ExternalLoginResult(Status status, AuthUser user, String challengeToken,
                                  OtpChannel channel, String destinationMasked,
                                  Long expiresInSeconds, Long resendAfterSeconds) {
    public enum Status { AUTHENTICATED, MFA_REQUIRED, MFA_ENROLLMENT_REQUIRED, OTP_REQUIRED, REJECTED }

    public static ExternalLoginResult authenticated(AuthUser user) {
        return new ExternalLoginResult(Status.AUTHENTICATED, user, null, null, null, null, null);
    }

    public static ExternalLoginResult mfaRequired(AuthUser user, String challengeToken) {
        return new ExternalLoginResult(Status.MFA_REQUIRED, user, challengeToken, null, null, null, null);
    }
    public static ExternalLoginResult mfaEnrollmentRequired(AuthUser user, String enrollmentToken) {
        return new ExternalLoginResult(Status.MFA_ENROLLMENT_REQUIRED, user, enrollmentToken, null, null, null, null);
    }

    public static ExternalLoginResult otpRequired(AuthUser user, LoginOtpService.IssuedChallenge challenge) {
        return new ExternalLoginResult(Status.OTP_REQUIRED, user, challenge.challengeToken(), challenge.channel(),
                challenge.destinationMasked(), challenge.expiresInSeconds(), challenge.resendAfterSeconds());
    }

    public static ExternalLoginResult rejected() {
        return new ExternalLoginResult(Status.REJECTED, null, null, null, null, null, null);
    }
}
