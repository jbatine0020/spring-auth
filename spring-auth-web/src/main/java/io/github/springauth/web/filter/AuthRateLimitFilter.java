package io.github.springauth.web.filter;

import java.io.IOException;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.error.AuthErrorCodes;
import io.github.springauth.core.port.RateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Per-address quota on the authentication endpoints.
 *
 * <p>The outer barrier against credential stuffing: without it, an attacker can drive the login
 * endpoint as fast as the server answers. It complements per-account lock-out rather than
 * replacing it. Lock-out stops many guesses against one account; this stops many accounts being
 * tried from one place.
 *
 * <p>Runs very early, ahead of the security chain, so a flood costs no BCrypt work. It counts by
 * the address the connection actually came from; {@code X-Forwarded-For} is not honoured, since a
 * client-supplied header would let the attacker mint a fresh quota per request. Behind a trusted
 * proxy, set {@code server.forward-headers-strategy=framework}.
 *
 * <p>The bean stays registered when disabled and simply passes through, so a test slice that mocks
 * it keeps working. Never disable it in production.
 */
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class AuthRateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AuthRateLimitFilter.class);

    private final RateLimiter rateLimiter;
    private final ErrorResponseWriter errorWriter;
    private final AuthProperties.RateLimit properties;
    private final Map<String, Integer> quotas;

    public AuthRateLimitFilter(RateLimiter rateLimiter,
                               ErrorResponseWriter errorWriter,
                               AuthProperties properties) {
        this.rateLimiter = rateLimiter;
        this.errorWriter = errorWriter;
        this.properties = properties.getRateLimit();
        this.quotas = buildQuotas(properties);
        if (!this.properties.isEnabled()) {
            log.warn("spring-auth: rate limiting is DISABLED, brute-force protection on /login "
                    + "is off. Never run this configuration in production.");
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (!properties.isEnabled()) {
            chain.doFilter(request, response);
            return;
        }
        Integer quota = quotas.get(request.getMethod() + " " + request.getRequestURI());
        if (quota == null) {
            chain.doFilter(request, response);
            return;
        }
        String key = request.getRequestURI() + "|" + clientAddress(request);
        Duration window = properties.getWindow();
        if (rateLimiter.tryAcquire(key, quota, window)) {
            chain.doFilter(request, response);
            return;
        }
        long retryAfter = Math.max(1, rateLimiter.retryAfter(key, quota, window).toSeconds());
        errorWriter.write(request, response, HttpStatus.TOO_MANY_REQUESTS, AuthErrorCodes.RATE_LIMITED,
                "Trop de tentatives, réessayez dans " + retryAfter + " secondes", retryAfter);
    }

    private static Map<String, Integer> buildQuotas(AuthProperties properties) {
        String base = properties.getWeb().getBasePath();
        AuthProperties.RateLimit limits = properties.getRateLimit();
        Map<String, Integer> quotas = new LinkedHashMap<>();
        quotas.put("POST " + base + "/login", limits.getLoginPerMinute());
        quotas.put("POST " + base + "/mfa/verify", limits.getMfaPerMinute());
        quotas.put("POST " + base + "/mfa/enrollment/start", limits.getMfaPerMinute());
        quotas.put("POST " + base + "/mfa/enrollment/confirm", limits.getMfaPerMinute());
        quotas.put("POST " + base + "/refresh", limits.getRefreshPerMinute());
        quotas.put("POST " + base + "/password-reset:request", limits.getPasswordResetPerMinute());
        quotas.put("POST " + base + "/password-reset:confirm", limits.getPasswordResetPerMinute());
        quotas.put("POST " + base + "/invitations:redeem", limits.getPasswordResetPerMinute());
        return Map.copyOf(quotas);
    }

    private static String clientAddress(HttpServletRequest request) {
        String address = request.getRemoteAddr();
        return address == null ? "unknown" : address;
    }
}
