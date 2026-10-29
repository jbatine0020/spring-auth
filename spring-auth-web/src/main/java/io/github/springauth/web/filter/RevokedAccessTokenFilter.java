package io.github.springauth.web.filter;

import java.io.IOException;
import java.time.Instant;
import java.util.OptionalLong;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import io.github.springauth.core.error.AuthErrorCodes;
import io.github.springauth.core.port.AccessTokenRevocationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Refuses access tokens issued before a revocation stamp.
 *
 * <p>A signed JWT cannot be withdrawn, so a logout or a password change would otherwise leave the
 * current access token working until it expires. This filter closes that gap by comparing the
 * token's {@code iat} against the stamp recorded for its subject.
 *
 * <p>It runs after the bearer token filter, once the security context holds a validated token.
 *
 * <p><b>Fail-open on store failure.</b> If the revocation store is unreachable the request is let
 * through, deliberately: the alternative locks every authenticated user out of the platform
 * because a cache is down. The window is bounded by the access TTL, and refresh tokens, which
 * live in the database, are already revoked, so a session cannot be renewed either way.
 */
public class RevokedAccessTokenFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RevokedAccessTokenFilter.class);

    private final AccessTokenRevocationStore revocationStore;
    private final ErrorResponseWriter errorWriter;

    public RevokedAccessTokenFilter(AccessTokenRevocationStore revocationStore,
                                    ErrorResponseWriter errorWriter) {
        this.revocationStore = revocationStore;
        this.errorWriter = errorWriter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof JwtAuthenticationToken token) || !isRevoked(token.getToken())) {
            chain.doFilter(request, response);
            return;
        }
        SecurityContextHolder.clearContext();
        errorWriter.write(request, response, HttpStatus.UNAUTHORIZED, AuthErrorCodes.SESSION_REVOKED,
                "Session expirée, veuillez vous reconnecter");
    }

    private boolean isRevoked(Jwt jwt) {
        String subject = jwt.getSubject();
        Instant issuedAt = jwt.getIssuedAt();
        if (subject == null || subject.isBlank() || issuedAt == null) {
            return false;
        }
        try {
            OptionalLong revokedSince = revocationStore.revokedSinceEpochSeconds(subject);
            return revokedSince.isPresent() && issuedAt.getEpochSecond() < revokedSince.getAsLong();
        } catch (RuntimeException ex) {
            log.error("spring-auth: revocation check unavailable for subject={}, failing open",
                    subject, ex);
            return false;
        }
    }
}
