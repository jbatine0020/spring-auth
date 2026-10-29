package io.github.springauth.web.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import jakarta.servlet.Filter;
import io.github.springauth.core.config.AuthProperties;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Assembles the security filter chain: stateless JWT resource server, public authentication
 * endpoints, hardening headers, and the library's own filters in the right order.
 *
 * <p>Applications that need a different chain set {@code spring-auth.web.security-chain-enabled}
 * to false and build their own; the pieces here stay reusable individually.
 */
public class AuthSecurityChainBuilder {

    private final AuthProperties properties;

    public AuthSecurityChainBuilder(AuthProperties properties) {
        this.properties = properties;
    }

    /**
     * Paths reachable without authentication: the endpoints through which a caller becomes
     * authenticated, plus whatever the application adds.
     *
     * <p>Each one is protected by the credential inside its own body: a password, a challenge
     * token, a refresh token, a reset link, and by rate limiting.
     */
    public String[] publicPaths() {
        String base = properties.getWeb().getBasePath();
        List<String> paths = new ArrayList<>(List.of(
                base + "/login",
                base + "/login/external",
                base + "/login/external/mfa",
                base + "/login/external/otp/verify",
                base + "/login/external/otp/resend",
                base + "/mfa/verify",
                base + "/mfa/enrollment/start",
                base + "/mfa/enrollment/confirm",
                base + "/refresh",
                base + "/password-reset:request",
                base + "/password-reset:confirm",
                base + "/password-policy",
                base + "/invitations:verify",
                base + "/invitations:redeem"));
        if (properties.getWeb().isJwksEnabled()) {
            paths.add("/.well-known/jwks.json");
        }
        paths.addAll(properties.getWeb().getPublicPaths());
        return paths.toArray(String[]::new);
    }

    /**
     * Builds the chain.
     *
     * @param internalAuthFilter service-to-service authentication, null when disabled
     * @param signatureFilter    body signature verification, null when disabled
     */
    public SecurityFilterChain build(HttpSecurity http,
                                     Filter revokedTokenFilter,
                                     Filter mustChangePasswordFilter,
                                     Filter internalAuthFilter,
                                     Filter signatureFilter) throws Exception {
        String[] publicPaths = publicPaths();

        http
                // No cookie-based session and no browser form, so CSRF tokens have nothing to
                // protect; the refresh cookie, when enabled, is SameSite=Strict for that reason.
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(registry -> registry
                        .requestMatchers(publicPaths).permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth -> oauth
                        .bearerTokenResolver(publicAwareBearerTokenResolver(publicPaths))
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())));

        if (properties.getWeb().isSecurityHeadersEnabled()) {
            http.headers(AuthSecurityChainBuilder::hardeningHeaders);
        }
        if (!properties.getWeb().getAllowedOrigins().isEmpty()) {
            http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
        }
        if (internalAuthFilter != null) {
            http.addFilterBefore(internalAuthFilter, UsernamePasswordAuthenticationFilter.class);
        }
        if (signatureFilter != null) {
            // After identification: the signing key is the secret of the peer just authenticated.
            http.addFilterAfter(signatureFilter, UsernamePasswordAuthenticationFilter.class);
        }
        // Both need a populated security context, so they run after the bearer token filter.
        http.addFilterAfter(revokedTokenFilter, BearerTokenAuthenticationFilter.class);
        http.addFilterAfter(mustChangePasswordFilter, BearerTokenAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Ignores the {@code Authorization} header on public endpoints.
     *
     * <p>Otherwise a client that still holds a stale or foreign bearer token gets a 401 from the
     * resource server before {@code permitAll()} ever applies, so logging in again becomes
     * impossible until the client clears its own storage. Sending a token to a public endpoint is
     * common enough (a leftover interceptor, a retried request) that this is worth handling.
     */
    private BearerTokenResolver publicAwareBearerTokenResolver(String[] publicPaths) {
        DefaultBearerTokenResolver delegate = new DefaultBearerTokenResolver();
        PathMatcher pathMatcher = new AntPathMatcher();
        List<String> patterns = List.of(publicPaths);
        return request -> {
            String path = request.getRequestURI();
            for (String pattern : patterns) {
                if (pathMatcher.match(pattern, path)) {
                    return null; // No token resolved means no validation, hence no premature 401.
                }
            }
            return delegate.resolve(request);
        };
    }

    /** Converts a validated token into an authentication, mapping the permission claim. */
    public Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
        String permissionClaim = properties.getJwt().getPermissionClaim();
        return jwt -> {
            rejectPurposeTokens(jwt);
            return new JwtAuthenticationToken(jwt, extractAuthorities(jwt, permissionClaim),
                    jwt.getSubject());
        };
    }

    /**
     * Refuses a token that carries a {@code purpose} claim.
     *
     * <p>Challenge and enrolment tokens share issuer, audience and signing key with access tokens,
     * so without this check they satisfy {@code anyRequest().authenticated()} and reach every
     * endpoint that is not additionally annotated: a complete MFA bypass for anyone who knows the
     * password.
     */
    private static void rejectPurposeTokens(Jwt jwt) {
        if (jwt.getClaim(io.github.springauth.core.jwt.TokenPurpose.CLAIM) != null) {
            throw new BadCredentialsException(
                    "Jeton à usage spécifique non utilisable comme jeton d'accès");
        }
    }

    private static Collection<GrantedAuthority> extractAuthorities(Jwt jwt, String claimName) {
        Object claim = jwt.getClaim(claimName);
        if (claim == null) {
            return Collections.emptyList();
        }
        List<String> raw = switch (claim) {
            case String value -> Arrays.asList(value.split("[\\s,]+"));
            case Collection<?> values -> values.stream().map(Object::toString).toList();
            default -> Collections.emptyList();
        };
        return raw.stream()
                .filter(value -> !value.isBlank())
                .map(String::trim)
                .<GrantedAuthority>map(SimpleGrantedAuthority::new)
                .toList();
    }

    /**
     * Transport and browser hardening: HSTS, a CSP tight enough for a JSON API, and a referrer
     * policy that stops tokens in query strings leaking cross-origin.
     */
    private static void hardeningHeaders(HeadersConfigurer<HttpSecurity> headers) {
        headers
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                        "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'"))
                .httpStrictTransportSecurity(hsts -> hsts
                        .includeSubDomains(true)
                        .maxAgeInSeconds(31_536_000))
                .referrerPolicy(referrer -> referrer.policy(
                        ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN));
    }

    /**
     * CORS restricted to the configured origins.
     *
     * <p>Explicit origins only, never a wildcard: combined with credentials, a reflected wildcard
     * lets any site issue authenticated cross-origin requests from a logged-in user's browser.
     */
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cors = new CorsConfiguration();
        cors.setAllowedOrigins(List.copyOf(properties.getWeb().getAllowedOrigins()));
        cors.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        cors.setAllowedHeaders(List.of("*"));
        cors.setAllowCredentials(true);
        cors.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cors);
        return source;
    }
}
