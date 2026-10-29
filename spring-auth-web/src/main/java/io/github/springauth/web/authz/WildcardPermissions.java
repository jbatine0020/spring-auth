package io.github.springauth.web.authz;

import io.github.springauth.core.model.Role;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Helpers for the wildcard permission {@code system:root}.
 *
 * <p>A role carrying it satisfies every authority check, which is what makes a break-glass account
 * workable without enumerating hundreds of permissions on it. Grant it to exactly one role and
 * treat holding that role as an auditable event.
 *
 * <p><b>Manual authority checks must go through {@link #holdsAuthority}.</b> Code that inspects
 * {@code getAuthorities()} directly bypasses the SpEL handler and silently ignores the wildcard, so
 * the break-glass account gets refused by precisely the branch it exists for. This is the classic
 * way the mechanism ends up half-working.
 */
public final class WildcardPermissions {

    /** The wildcard permission itself. */
    public static final String WILDCARD = Role.WILDCARD_PERMISSION;

    private WildcardPermissions() {
        // utility
    }

    /**
     * Wildcard-aware equivalent of {@code hasAuthority(...)}, for checks outside SpEL: tenant
     * scoping in a controller, post-query filtering, a conditional branch in a service.
     *
     * @return true when the authentication carries {@code target} or the wildcard
     */
    public static boolean holdsAuthority(Authentication authentication, String target) {
        if (authentication == null || target == null) {
            return false;
        }
        for (GrantedAuthority granted : authentication.getAuthorities()) {
            String value = granted.getAuthority();
            if (WILDCARD.equals(value) || target.equals(value)) {
                return true;
            }
        }
        return false;
    }

    /** True when the authentication carries the wildcard. */
    public static boolean holdsWildcard(Authentication authentication) {
        if (authentication == null) {
            return false;
        }
        for (GrantedAuthority granted : authentication.getAuthorities()) {
            if (WILDCARD.equals(granted.getAuthority())) {
                return true;
            }
        }
        return false;
    }
}
