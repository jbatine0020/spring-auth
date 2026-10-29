package io.github.springauth.web.authz;

import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;

/**
 * SpEL root that makes {@code hasAuthority(...)} and {@code hasAnyAuthority(...)} honour the
 * wildcard permission.
 *
 * <p>Without it every {@code @PreAuthorize} in an application would have to be written as
 * {@code hasAnyAuthority('x', 'system:root')}: noisy, and easy to forget on the one endpoint
 * where it matters.
 *
 * <p>Implemented by full delegation rather than by extending {@code SecurityExpressionRoot}: that
 * class declares its authority methods {@code final}, so subclassing cannot change their answer.
 * Everything except the four authority checks is handed straight to the standard root, which keeps
 * {@code @PreFilter} and {@code @PostFilter} working on the instance the framework populated.
 */
public class WildcardMethodSecurityExpressionRoot implements MethodSecurityExpressionOperations {

    private final MethodSecurityExpressionOperations delegate;
    private final Authentication authentication;

    public WildcardMethodSecurityExpressionRoot(MethodSecurityExpressionOperations delegate,
                                                Authentication authentication) {
        this.delegate = delegate;
        this.authentication = authentication;
    }

    @Override
    public boolean hasAuthority(String authority) {
        return holdsWildcard() || delegate.hasAuthority(authority);
    }

    @Override
    public boolean hasAnyAuthority(String... authorities) {
        return holdsWildcard() || delegate.hasAnyAuthority(authorities);
    }

    @Override
    public boolean hasRole(String role) {
        return holdsWildcard() || delegate.hasRole(role);
    }

    @Override
    public boolean hasAnyRole(String... roles) {
        return holdsWildcard() || delegate.hasAnyRole(roles);
    }

    private boolean holdsWildcard() {
        return WildcardPermissions.holdsWildcard(authentication);
    }

    @Override
    public Authentication getAuthentication() {
        return delegate.getAuthentication();
    }

    /**
     * Exposes {@code principal} to SpEL expressions.
     *
     * <p>Not declared on {@code SecurityExpressionOperations}, the standard root offers it as a
     * plain accessor, so it is provided here for expressions such as
     * {@code @PreAuthorize("#id == principal")}.
     */
    public Object getPrincipal() {
        return authentication == null ? null : authentication.getPrincipal();
    }

    @Override
    public boolean permitAll() {
        return delegate.permitAll();
    }

    @Override
    public boolean denyAll() {
        return delegate.denyAll();
    }

    @Override
    public boolean isAnonymous() {
        return delegate.isAnonymous();
    }

    @Override
    public boolean isAuthenticated() {
        return delegate.isAuthenticated();
    }

    @Override
    public boolean isRememberMe() {
        return delegate.isRememberMe();
    }

    @Override
    public boolean isFullyAuthenticated() {
        return delegate.isFullyAuthenticated();
    }

    @Override
    public boolean hasPermission(Object target, Object permission) {
        return delegate.hasPermission(target, permission);
    }

    @Override
    public boolean hasPermission(Object targetId, String targetType, Object permission) {
        return delegate.hasPermission(targetId, targetType, permission);
    }

    @Override
    public Object getFilterObject() {
        return delegate.getFilterObject();
    }

    @Override
    public void setFilterObject(Object filterObject) {
        delegate.setFilterObject(filterObject);
    }

    @Override
    public Object getReturnObject() {
        return delegate.getReturnObject();
    }

    @Override
    public void setReturnObject(Object returnObject) {
        delegate.setReturnObject(returnObject);
    }

    @Override
    public Object getThis() {
        return delegate.getThis();
    }
}
