package io.github.springauth.web.internal;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.error.AuthErrorCodes;
import io.github.springauth.core.internal.BodySignature;
import io.github.springauth.web.filter.ErrorResponseWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Verifies the HMAC signature of a request body.
 *
 * <p>Runs after {@link InternalServiceAuthFilter}, so the signing key is the secret of the peer
 * that already proved its identity: the token says who is calling, the signature says the payload
 * was not modified in between.
 *
 * <p>Only applies to requests that carry the signature header and come from an authenticated peer;
 * everything else passes through untouched.
 */
public class WebhookSignatureFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(WebhookSignatureFilter.class);

    private final ErrorResponseWriter errorWriter;
    private final AuthProperties.Internal properties;

    public WebhookSignatureFilter(ErrorResponseWriter errorWriter, AuthProperties.Internal properties) {
        this.errorWriter = errorWriter;
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String providedSignature = request.getHeader(properties.getSignatureHeader());
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (providedSignature == null || providedSignature.isBlank()
                || !(authentication instanceof InternalAuthentication internal)) {
            chain.doFilter(request, response);
            return;
        }

        String peer = internal.getIdentity().serviceId();
        String secret = properties.getPeers().get(peer);
        if (secret == null || secret.isBlank()) {
            log.warn("spring-auth: no secret configured to verify the signature of peer {}", peer);
            errorWriter.write(request, response, HttpStatus.UNAUTHORIZED,
                    AuthErrorCodes.INTERNAL_AUTH_FAILED, "Signature non vérifiable");
            return;
        }

        // Wrapped so the controller can still read the body after the filter consumed it.
        CachedBodyHttpServletRequest cached = new CachedBodyHttpServletRequest(request);
        if (!BodySignature.verify(secret, cached.getCachedBody(), providedSignature)) {
            log.warn("spring-auth: bad body signature from peer {}", peer);
            errorWriter.write(request, response, HttpStatus.UNAUTHORIZED,
                    AuthErrorCodes.INTERNAL_AUTH_FAILED, "Signature invalide");
            return;
        }
        chain.doFilter(cached, response);
    }
}
