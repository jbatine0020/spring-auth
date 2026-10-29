package io.github.springauth.core.error;

/**
 * Every error code spring-auth can produce, with the HTTP status the web module maps it to.
 *
 * <p>These strings are part of the public contract: front-ends branch on them and integration
 * tests assert them. They are intentionally coarse on the authentication path; see
 * {@link #LOGIN_INVALID}, because distinguishing "unknown account" from "wrong password"
 * hands account enumeration to an attacker.
 */
public final class AuthErrorCodes {

    /**
     * Generic authentication failure (401).
     *
     * <p>Returned for unknown login, wrong password, disabled account, not-yet-activated
     * account and locked account alike. The precise reason is recorded in the login history
     * for operators, never disclosed to the caller.
     */
    public static final String LOGIN_INVALID = "LOGIN_INVALID";

    /** The password matched but the account is locked out after repeated failures (401). */
    public static final String ACCOUNT_LOCKED = "ACCOUNT_LOCKED";

    /** A step-up confirmation is required and no code was supplied (401). */
    public static final String MFA_REQUIRED = "MFA_REQUIRED";

    /** The submitted TOTP code is wrong, expired or replayed (401). */
    public static final String MFA_INVALID_CODE = "MFA_INVALID_CODE";

    /** Too many invalid TOTP codes; verification is locked for a cool-down period (429). */
    public static final String MFA_LOCKED = "MFA_LOCKED";

    /** No enrolled factor while one is required (409). */
    public static final String MFA_NOT_ENROLLED = "MFA_NOT_ENROLLED";

    /** The short-lived challenge or enrolment token is invalid or expired (401). */
    public static final String MFA_CHALLENGE_INVALID = "MFA_CHALLENGE_INVALID";

    /** Refresh token unknown, expired or already revoked (401). */
    public static final String REFRESH_TOKEN_INVALID = "REFRESH_TOKEN_INVALID";

    /**
     * A revoked refresh token was presented again (401).
     *
     * <p>Treated as theft: the whole token family is invalidated, logging out both the
     * attacker and the legitimate holder.
     */
    public static final String REFRESH_TOKEN_REPLAY = "REFRESH_TOKEN_REPLAY";

    /** The access token was issued before a revocation stamp (401). */
    public static final String SESSION_REVOKED = "SESSION_REVOKED";

    /** The password is shorter than the configured minimum (400). */
    public static final String PASSWORD_TOO_SHORT = "PASSWORD_TOO_SHORT";

    /** The password misses one of the required character classes (400). */
    public static final String PASSWORD_TOO_WEAK = "PASSWORD_TOO_WEAK";

    /** The password matches one of the user's recent passwords (400). */
    public static final String PASSWORD_REUSED = "PASSWORD_REUSED";

    /** The supplied current password does not match (400). */
    public static final String PASSWORD_MISMATCH = "PASSWORD_MISMATCH";

    /** The caller must change its password before doing anything else (403). */
    public static final String PASSWORD_CHANGE_NOT_REQUIRED = "PASSWORD_CHANGE_NOT_REQUIRED";
    public static final String PASSWORD_CHANGE_REQUIRED = "PASSWORD_CHANGE_REQUIRED";

    /** Reset link unknown or malformed (400). */
    public static final String PASSWORD_RESET_INVALID = "PASSWORD_RESET_INVALID";

    /** Reset link past its validity window (400). */
    public static final String PASSWORD_RESET_EXPIRED = "PASSWORD_RESET_EXPIRED";

    /** Reset link already consumed (400). */
    public static final String PASSWORD_RESET_ALREADY_USED = "PASSWORD_RESET_ALREADY_USED";

    /** Too many wrong OTP codes on the same reset link (400). */
    public static final String PASSWORD_RESET_LOCKED = "PASSWORD_RESET_LOCKED";

    /** Invitation token unknown, expired or already redeemed (400). */
    public static final String INVITATION_INVALID = "INVITATION_INVALID";

    /** Per-IP quota exceeded on an authentication endpoint (429). */
    public static final String RATE_LIMITED = "RATE_LIMITED";

    /** The requested role does not exist (404). */
    public static final String ROLE_NOT_FOUND = "ROLE_NOT_FOUND";

    /** A role with the same code already exists (409). */
    public static final String ROLE_ALREADY_EXISTS = "ROLE_ALREADY_EXISTS";

    /** Service-to-service authentication failed (401). */
    public static final String INTERNAL_AUTH_FAILED = "INTERNAL_AUTH_FAILED";

    private AuthErrorCodes() {
        // constants holder
    }
}
