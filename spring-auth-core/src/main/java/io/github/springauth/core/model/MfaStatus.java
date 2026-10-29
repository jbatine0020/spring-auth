package io.github.springauth.core.model;

/**
 * Enrolment state of a user's second factor.
 *
 * <p>Derived, never stored on the user: it is computed from {@link MfaRequirement} and the
 * MFA credential owned by the library. That keeps the host application free of any MFA
 * bookkeeping.
 */
public enum MfaStatus {

    /** MFA does not apply to this user. */
    NOT_APPLICABLE,

    /** MFA applies but no confirmed factor exists yet. The user must enrol. */
    NOT_CONFIGURED,

    /** A TOTP factor has been enrolled and confirmed by a first valid code. */
    CONFIGURED,

    /** An administrator wiped the factor; the user must enrol again before authenticating. */
    RESET_PENDING
}
