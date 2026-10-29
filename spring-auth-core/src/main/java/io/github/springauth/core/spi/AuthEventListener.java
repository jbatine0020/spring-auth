package io.github.springauth.core.spi;

import java.time.Instant;

import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.LoginFailureReason;
import io.github.springauth.core.model.RequestContext;

/**
 * Observability hook over the authentication lifecycle: audit trails, SIEM feeds, metrics,
 * domain events.
 *
 * <p>Distinct from {@link AuthMessenger}, which delivers secrets to end users. Nothing here
 * carries a credential, so these callbacks are safe to log and forward.
 *
 * <p>Every method defaults to doing nothing. Implement the ones you care about. Implementations
 * must not throw: a failing listener is caught and logged by the library rather than turned into
 * a failed login, since an audit backend being down is not a reason to lock everyone out.
 */
public interface AuthEventListener {

    default void onLoginSucceeded(AuthUser user, RequestContext context, Instant at) {
        // no-op by default
    }

    /**
     * @param userId null when the submitted login matched no account
     * @param login  the value that was submitted, useful to spot enumeration sweeps
     */
    default void onLoginFailed(AuthUserId userId, String login, LoginFailureReason reason,
                               RequestContext context, Instant at) {
        // no-op by default
    }

    /** The account just crossed the failure threshold and is now locked. */
    default void onAccountLocked(AuthUser user, Instant lockedUntil, RequestContext context) {
        // no-op by default
    }

    default void onMfaEnrolled(AuthUser user, Instant at) {
        // no-op by default
    }

    default void onMfaVerificationFailed(AuthUser user, RequestContext context, Instant at) {
        // no-op by default
    }

    /** An administrator wiped the user's factor; they must enrol again. */
    default void onMfaReset(AuthUser user, String performedBy, Instant at) {
        // no-op by default
    }

    default void onPasswordChanged(AuthUser user, boolean selfService, Instant at) {
        // no-op by default
    }

    default void onPasswordResetRequested(AuthUser user, RequestContext context, Instant at) {
        // no-op by default
    }

    /**
     * A revoked refresh token was presented again and the whole family was invalidated.
     * Worth an alert: it means a token leaked.
     */
    default void onRefreshTokenReplayDetected(AuthUserId userId, RequestContext context, Instant at) {
        // no-op by default
    }

    default void onLogout(AuthUserId userId, Instant at) {
        // no-op by default
    }

    /**
     * An invitation was redeemed and the initial password is set.
     *
     * <p>This is where a host application flips its own user record from "invited" to "active":
     * the library owns the credential, the application owns the account state.
     */
    default void onInvitationRedeemed(AuthUser user, Instant at) {
        // no-op by default
    }
}
