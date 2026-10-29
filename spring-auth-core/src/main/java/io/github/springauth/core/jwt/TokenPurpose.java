package io.github.springauth.core.jwt;

/**
 * Marks the short-lived tokens issued in the middle of an authentication flow.
 *
 * <p>These share issuer, audience and signing key with access tokens but must never be accepted
 * as one: their holder has proved a password and nothing more. The resource server rejects any
 * token carrying a {@code purpose} claim, which is what stops a challenge token from reaching an
 * endpoint that only requires {@code authenticated()} and silently bypassing MFA.
 */
public enum TokenPurpose {

    /** Issued between the password step and the TOTP step for a user who already enrolled. */
    MFA_CHALLENGE("mfa_challenge"),

    /** Issued after the password step for a user who still has to enrol a factor. */
    MFA_ENROLLMENT("mfa_enrollment"),

    /** Issued between external password validation and EMAIL_OTP/SMS_OTP verification. */
    LOGIN_OTP("login_otp");

    /** Name of the claim carrying the purpose. */
    public static final String CLAIM = "purpose";

    private final String claimValue;

    TokenPurpose(String claimValue) {
        this.claimValue = claimValue;
    }

    public String claimValue() {
        return claimValue;
    }
}
