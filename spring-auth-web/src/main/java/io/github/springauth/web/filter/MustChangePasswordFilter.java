package io.github.springauth.web.filter;

import java.io.IOException;
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.error.AuthErrorCodes;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Enforces a forced password change on the server side.
 *
 * <p>The {@code must_change_password} claim is set when an administrator resets a password or when
 * one ages out. Left as a hint for the front-end, it is trivially ignored: a user, or an attacker
 * holding a temporary password, just skips the redirect and keeps working. This filter makes the
 * flag binding by refusing every request except the ones needed to get out of the state.
 *
 * <p>What stays reachable: the password change endpoint itself, logout, and CORS preflights.
 * Everything else gets 403 {@code PASSWORD_CHANGE_REQUIRED}. Once the password is changed the flag
 * is cleared in storage, and the next token comes without the claim.
 *
 * <p>Inert when no JWT is present, so it never interferes with the unauthenticated endpoints.
 */
public class MustChangePasswordFilter extends OncePerRequestFilter {

    /** Claim written by the issuer and read here. */
    public static final String CLAIM = "must_change_password";

    private final Set<String> allowedPaths;

    public MustChangePasswordFilter(AuthProperties properties) {
        String base = properties.getWeb().getBasePath();
        this.allowedPaths = Set.of(base + "/password:change", base + "/password:first-change", base + "/logout");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (!mustChangePassword() || isAllowed(request)) {
            chain.doFilter(request, response);
            return;
        }
        writeBlocked(request, response);
    }

    private boolean mustChangePassword() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication instanceof JwtAuthenticationToken token
                && Boolean.TRUE.equals(token.getToken().getClaim(CLAIM));
    }

    private boolean isAllowed(HttpServletRequest request) {
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }
        return "POST".equalsIgnoreCase(request.getMethod())
                && allowedPaths.contains(request.getRequestURI());
    }

    private void writeBlocked(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        // Written directly rather than thrown: this filter sits outside the dispatcher, so no
        // controller advice would ever see the exception.
        response.reset();
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType("application/json;charset=UTF-8");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"status\":403,\"error\":\"Forbidden\",\"code\":\""
                + AuthErrorCodes.PASSWORD_CHANGE_REQUIRED
                + "\",\"message\":\"Vous devez changer votre mot de passe avant de poursuivre\",\"path\":\""
                + escape(request.getRequestURI()) + "\"}");
    }

    private static String escape(String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
