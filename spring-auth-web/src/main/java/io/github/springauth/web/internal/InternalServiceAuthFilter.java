package io.github.springauth.web.internal;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.error.AuthErrorCodes;
import io.github.springauth.core.error.InternalAuthException;
import io.github.springauth.core.internal.InternalTokenService;
import io.github.springauth.core.internal.ServiceIdentity;
import io.github.springauth.web.filter.ErrorResponseWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates a peer service from the internal token header.
 *
 * <p>Runs before the bearer-token filter, so an internal call never needs a user token. Requests
 * without the header pass straight through and are handled as ordinary user traffic.
 *
 * <p>A header that is present but invalid is rejected outright rather than ignored. Falling
 * through to anonymous would turn a forged token into a silent downgrade, and the caller would
 * discover the problem as a confusing 403 much later.
 */
public class InternalServiceAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(InternalServiceAuthFilter.class);

    private final InternalTokenService tokenService;
    private final ErrorResponseWriter errorWriter;
    private final String tokenHeader;

    public InternalServiceAuthFilter(InternalTokenService tokenService,
                                     ErrorResponseWriter errorWriter,
                                     AuthProperties.Internal properties) {
        this.tokenService = tokenService;
        this.errorWriter = errorWriter;
        this.tokenHeader = properties.getTokenHeader();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String token = request.getHeader(tokenHeader);
        if (token == null || token.isBlank()) {
            chain.doFilter(request, response);
            return;
        }
        try {
            ServiceIdentity identity = tokenService.validate(token);
            SecurityContextHolder.getContext().setAuthentication(new InternalAuthentication(identity));
        } catch (InternalAuthException ex) {
            SecurityContextHolder.clearContext();
            log.warn("spring-auth: internal call refused, {}", ex.getReason());
            errorWriter.write(request, response, HttpStatus.UNAUTHORIZED,
                    AuthErrorCodes.INTERNAL_AUTH_FAILED, ex.getMessage());
            return;
        }
        chain.doFilter(request, response);
    }
}
