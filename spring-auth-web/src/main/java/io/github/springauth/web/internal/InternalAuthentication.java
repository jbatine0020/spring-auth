package io.github.springauth.web.internal;

import java.util.Collection;
import java.util.List;

import io.github.springauth.core.internal.ServiceIdentity;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Authentication of a peer service rather than a human.
 *
 * <p>Carries two authorities: {@code ROLE_INTERNAL_SERVICE}, so an endpoint can require "any
 * internal caller", and {@code internal:<serviceId>}, so it can require one specific peer. The
 * finer one matters: sharing a trust boundary between services is not the same as letting every
 * service call every endpoint.
 *
 * <p>Deliberately carries no user permission. An internal call acts as a service, not on behalf of
 * a user, and conflating the two is how a machine account ends up with more reach than any person.
 */
public class InternalAuthentication extends AbstractAuthenticationToken {

    /** Authority every authenticated peer carries. */
    public static final String INTERNAL_ROLE = "ROLE_INTERNAL_SERVICE";

    /** Prefix of the per-peer authority. */
    public static final String SERVICE_AUTHORITY_PREFIX = "internal:";

    private final ServiceIdentity identity;

    public InternalAuthentication(ServiceIdentity identity) {
        super(authoritiesFor(identity));
        this.identity = identity;
        setAuthenticated(true);
    }

    private static Collection<GrantedAuthority> authoritiesFor(ServiceIdentity identity) {
        return List.of(
                new SimpleGrantedAuthority(INTERNAL_ROLE),
                new SimpleGrantedAuthority(SERVICE_AUTHORITY_PREFIX + identity.serviceId()));
    }

    public ServiceIdentity getIdentity() {
        return identity;
    }

    @Override
    public Object getCredentials() {
        // The token was consumed during validation and is not kept: nothing to expose here.
        return null;
    }

    @Override
    public Object getPrincipal() {
        return identity.serviceId();
    }

    @Override
    public String getName() {
        return identity.serviceId();
    }
}
