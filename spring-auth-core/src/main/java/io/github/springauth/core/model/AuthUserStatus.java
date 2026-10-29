package io.github.springauth.core.model;

/**
 * Account status gating authentication.
 *
 * <p>Only {@link #ACTIVE} users may authenticate. Every other status is rejected with the same
 * generic {@code LOGIN_INVALID} error so an attacker cannot tell an existing account from an
 * unknown one; the precise reason is kept in the login history.
 */
public enum AuthUserStatus {

    /** Fully enabled account. */
    ACTIVE,

    /** Invited but never activated. The invitation link has not been redeemed yet. */
    PENDING_ACTIVATION,

    /** Temporarily disabled by an administrator. */
    DISABLED,

    /** Permanently archived; kept for audit purposes only. */
    ARCHIVED
}
