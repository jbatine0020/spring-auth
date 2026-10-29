package io.github.springauth.autoconfigure;

import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.internal.InternalTokenService;
import io.github.springauth.core.jwt.JwtKeyProvider;
import io.github.springauth.core.port.AccessTokenRevocationStore;
import io.github.springauth.core.port.RateLimiter;
import io.github.springauth.core.service.InvitationService;
import io.github.springauth.core.service.LoginHistoryService;
import io.github.springauth.core.service.LoginService;
import io.github.springauth.core.service.MfaService;
import io.github.springauth.core.service.PasswordService;
import io.github.springauth.core.service.RoleService;
import io.github.springauth.core.service.SessionService;
import io.github.springauth.core.spi.AuthUserDirectory;
import io.github.springauth.web.authz.WildcardMethodSecurityExpressionHandler;
import io.github.springauth.web.controller.AuthAdminController;
import io.github.springauth.web.controller.AuthController;
import io.github.springauth.web.controller.JwksController;
import io.github.springauth.web.controller.RoleController;
import io.github.springauth.web.error.AuthExceptionHandler;
import io.github.springauth.web.filter.AuthRateLimitFilter;
import io.github.springauth.web.filter.ErrorResponseWriter;
import io.github.springauth.web.filter.MustChangePasswordFilter;
import io.github.springauth.web.filter.RevokedAccessTokenFilter;
import io.github.springauth.web.internal.InternalServiceAuthFilter;
import io.github.springauth.web.internal.WebhookSignatureFilter;
import io.github.springauth.web.security.AuthSecurityChainBuilder;
import io.github.springauth.web.stepup.StepUpEnforcer;
import io.github.springauth.web.stepup.StepUpInterceptor;
import io.github.springauth.web.support.RefreshTokenCookies;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Wires the HTTP layer: endpoints, filters, method security and the security chain.
 *
 * <p>Three switches carve out what you keep:
 * <ul>
 *   <li>{@code spring-auth.web.enabled=false} drops the controllers, keeping the filters and the
 *       services, for an application that exposes its own API shape.</li>
 *   <li>{@code spring-auth.web.security-chain-enabled=false} drops the {@code SecurityFilterChain}
 *       so you can build your own, while the filters stay available as beans.</li>
 *   <li>{@code spring-auth.web.jwks-enabled=false} stops publishing the public keys.</li>
 * </ul>
 *
 * <p>Method security is enabled unconditionally. If it depended on a property, forgetting that
 * property in one environment would silently turn every {@code @PreAuthorize} in the application
 * into a no-op, a failure mode that looks exactly like everything working.
 */
@AutoConfiguration(after = SpringAuthAutoConfiguration.class)
@ConditionalOnClass({SecurityFilterChain.class, HttpSecurity.class})
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "spring-auth", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableMethodSecurity
public class SpringAuthWebAutoConfiguration {

    /**
     * Makes {@code @PreAuthorize} honour the wildcard permission.
     *
     * <p>{@code static} because method security is initialised very early; a non-static factory
     * method would drag this configuration into that phase and break auto-proxying of its
     * neighbours.
     */
    @Bean
    @ConditionalOnMissingBean(MethodSecurityExpressionHandler.class)
    static MethodSecurityExpressionHandler springAuthMethodSecurityExpressionHandler() {
        return new WildcardMethodSecurityExpressionHandler();
    }

    /**
     * Validates tokens against the local key set.
     *
     * <p>Declared only when the application has not configured an issuer of its own: an application
     * consuming tokens from an external identity provider keeps Spring Boot's decoder, which knows
     * how to fetch that provider's keys.
     */
    @Bean
    @ConditionalOnMissingBean(JwtDecoder.class)
    @ConditionalOnProperty(prefix = "spring.security.oauth2.resourceserver.jwt", name = "issuer-uri",
            matchIfMissing = true)
    public JwtDecoder springAuthJwtDecoder(JwtKeyProvider keyProvider) {
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(keyProvider.getJwkSet());
        ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
        processor.setJWSKeySelector(keySelector);
        return new NimbusJwtDecoder(processor);
    }

    @Bean
    @ConditionalOnMissingBean
    public ErrorResponseWriter springAuthErrorResponseWriter(ObjectMapper objectMapper) {
        return new ErrorResponseWriter(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthExceptionHandler springAuthExceptionHandler() {
        return new AuthExceptionHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenCookies springAuthRefreshTokenCookies(AuthProperties properties) {
        return new RefreshTokenCookies(properties.getSession());
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthSecurityChainBuilder springAuthSecurityChainBuilder(AuthProperties properties) {
        return new AuthSecurityChainBuilder(properties);
    }

    // ---- Filters ----------------------------------------------------------------------------

    @Bean
    @ConditionalOnMissingBean
    public AuthRateLimitFilter springAuthRateLimitFilter(RateLimiter rateLimiter,
                                                         ErrorResponseWriter errorWriter,
                                                         AuthProperties properties) {
        return new AuthRateLimitFilter(rateLimiter, errorWriter, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public RevokedAccessTokenFilter springAuthRevokedAccessTokenFilter(
            AccessTokenRevocationStore revocationStore, ErrorResponseWriter errorWriter) {
        return new RevokedAccessTokenFilter(revocationStore, errorWriter);
    }

    @Bean
    @ConditionalOnMissingBean
    public MustChangePasswordFilter springAuthMustChangePasswordFilter(AuthProperties properties) {
        return new MustChangePasswordFilter(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(InternalTokenService.class)
    public InternalServiceAuthFilter springAuthInternalServiceAuthFilter(
            InternalTokenService tokenService, ErrorResponseWriter errorWriter,
            AuthProperties properties) {
        return new InternalServiceAuthFilter(tokenService, errorWriter, properties.getInternal());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(InternalTokenService.class)
    public WebhookSignatureFilter springAuthWebhookSignatureFilter(ErrorResponseWriter errorWriter,
                                                                   AuthProperties properties) {
        return new WebhookSignatureFilter(errorWriter, properties.getInternal());
    }

    /**
     * The security chain.
     *
     * <p>{@code @ConditionalOnMissingBean(SecurityFilterChain.class)} means an application that
     * declares its own chain keeps full control and this one steps aside.
     */
    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    @ConditionalOnProperty(prefix = "spring-auth.web", name = "security-chain-enabled",
            havingValue = "true", matchIfMissing = true)
    public SecurityFilterChain springAuthSecurityFilterChain(
            HttpSecurity http,
            AuthSecurityChainBuilder builder,
            RevokedAccessTokenFilter revokedAccessTokenFilter,
            MustChangePasswordFilter mustChangePasswordFilter,
            ObjectProvider<InternalServiceAuthFilter> internalAuthFilter,
            ObjectProvider<WebhookSignatureFilter> signatureFilter) throws Exception {
        return builder.build(http, revokedAccessTokenFilter, mustChangePasswordFilter,
                internalAuthFilter.getIfAvailable(), signatureFilter.getIfAvailable());
    }

    // ---- Step-up ----------------------------------------------------------------------------

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnBean(AuthUserDirectory.class)
    @ConditionalOnProperty(prefix = "spring-auth.mfa", name = "step-up-enabled",
            havingValue = "true", matchIfMissing = true)
    static class StepUpConfiguration implements WebMvcConfigurer {

        private final StepUpInterceptor interceptor;

        StepUpConfiguration(MfaService mfaService, AuthUserDirectory userDirectory,
                            AuthProperties properties) {
            this.interceptor = new StepUpInterceptor(
                    new StepUpEnforcer(mfaService, userDirectory, properties.getMfa()));
        }

        @Override
        public void addInterceptors(InterceptorRegistry registry) {
            registry.addInterceptor(interceptor);
        }

        @Bean
        StepUpEnforcer springAuthStepUpEnforcer(MfaService mfaService, AuthUserDirectory userDirectory,
                                                AuthProperties properties) {
            return new StepUpEnforcer(mfaService, userDirectory, properties.getMfa());
        }
    }

    // ---- Controllers ------------------------------------------------------------------------
    //
    // Declared at this level rather than in a nested @Configuration. Nested member classes are
    // parsed before the enclosing auto-configuration's own beans, and a @ConditionalOnBean
    // evaluated there does not see what the surrounding ordering guarantees, the beans are then
    // skipped in silence and every endpoint answers 404 with nothing in the logs.

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(AuthUserDirectory.class)
    @ConditionalOnProperty(prefix = "spring-auth.web", name = "enabled", havingValue = "true",
            matchIfMissing = true)
    public AuthController springAuthController(LoginService loginService,
                                               MfaService mfaService,
                                               SessionService sessionService,
                                               PasswordService passwordService,
                                               InvitationService invitationService,
                                               LoginHistoryService loginHistoryService,
                                               RefreshTokenCookies refreshCookies,
                                               AuthProperties properties) {
        return new AuthController(loginService, mfaService, sessionService, passwordService,
                invitationService, loginHistoryService, refreshCookies, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(AuthUserDirectory.class)
    @ConditionalOnProperty(prefix = "spring-auth.web", name = "enabled", havingValue = "true",
            matchIfMissing = true)
    public AuthAdminController springAuthAdminController(PasswordService passwordService,
                                                         MfaService mfaService,
                                                         SessionService sessionService,
                                                         InvitationService invitationService,
                                                         LoginHistoryService loginHistoryService) {
        return new AuthAdminController(passwordService, mfaService, sessionService,
                invitationService, loginHistoryService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring-auth.web", name = "enabled", havingValue = "true",
            matchIfMissing = true)
    public RoleController springAuthRoleController(RoleService roleService) {
        return new RoleController(roleService);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring-auth.web", name = "jwks-enabled",
            havingValue = "true", matchIfMissing = true)
    public JwksController springAuthJwksController(JwtKeyProvider keyProvider) {
        return new JwksController(keyProvider);
    }
}
