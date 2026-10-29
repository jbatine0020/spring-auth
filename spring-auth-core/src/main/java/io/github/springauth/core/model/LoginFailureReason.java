package io.github.springauth.core.model;

/**
 * Why an authentication attempt failed.
 *
 * <p>Recorded in the login history, never returned to the caller: the API answers every one of
 * these with the same {@code LOGIN_INVALID}. Operators get the detail, attackers get nothing.
 */
public enum LoginFailureReason {

    /** No account matches the submitted login. */
    UNKNOWN_LOGIN,

    /** The account exists but the password does not match. */
    BAD_PASSWORD,

    /** The account is locked after repeated failures. */
    LOCKED,

    /** The account is disabled or archived. */
    DISABLED,

    /** The invitation was never redeemed. */
    NOT_ACTIVATED,

    /** No password has ever been set for this account. */
    NO_PASSWORD,

    /** The submitted TOTP code was wrong, expired or replayed. */
    BAD_MFA_CODE,

    /** MFA verification is locked after repeated failures. */
    MFA_LOCKED,

    /** The host application vetoed the attempt through its own rule. */
    REJECTED_BY_APPLICATION
}
