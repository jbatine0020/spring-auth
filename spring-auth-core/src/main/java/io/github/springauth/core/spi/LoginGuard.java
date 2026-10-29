package io.github.springauth.core.spi;

import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.RequestContext;

/**
 * Application-specific veto over an otherwise valid authentication.
 *
 * <p>Some rules do not belong to a generic library but must still run inside the login flow:
 * a back-office portal reserved to staff, a customer whose organisation is suspended, a country
 * or time-window restriction. Implement this to express them.
 *
 * <p>The guard runs <b>after</b> the password check and <b>before</b> any token or MFA challenge
 * is issued. That ordering matters: rejecting earlier would let a caller probe the rule without
 * knowing the password, and rejecting later would already have handed out a credential.
 *
 * <p>Throw any {@link io.github.springauth.core.error.AuthException} to refuse. Prefer a
 * specific code over the generic one here. At this point the caller has proved they own the
 * account, so an explicit "this portal is not for you" leaks nothing and saves a support call.
 */
@FunctionalInterface
public interface LoginGuard {

    /**
     * @param user    the authenticated user
     * @param context caller metadata
     * @throws io.github.springauth.core.error.AuthException to refuse the login
     */
    void check(AuthUser user, RequestContext context);

    /** Accepts everything. Default when the application registers no guard. */
    static LoginGuard permitAll() {
        return (user, context) -> {
            // nothing to check
        };
    }
}
