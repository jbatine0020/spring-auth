# Extending

Every bean the library declares is `@ConditionalOnMissingBean`, so replacing any single piece means
declaring your own bean of the same type. Nothing needs to be forked.

## The SPI

Four interfaces sit between the library and your application.

| Interface | Mandatory | Purpose |
|---|---|---|
| `AuthUserDirectory` | **yes** | Resolves your users into the projection the library needs |
| `AuthMessenger` | in practice | Delivers reset codes and invitation links |
| `AuthEventListener` | no | Observes the lifecycle: audit, SIEM, metrics, domain events |
| `LoginGuard` | no | Vetoes an otherwise valid authentication with your own rule |

### `LoginGuard`

Some rules belong to the application but must run inside the login flow: a back-office portal
reserved to staff, a customer whose organisation is suspended, a country restriction.

```java
@Component
class PortalGuard implements LoginGuard {

    @Override
    public void check(AuthUser user, RequestContext context) {
        if (isAdminPortal(context) && !isStaff(user)) {
            throw new PortalForbiddenException();   // extends AuthException
        }
    }
}
```

It runs **after** the password check and **before** any token or challenge is issued. That ordering
matters: refusing earlier lets a caller probe the rule without knowing the password, refusing later
means a credential has already been handed out.

At that point the caller has proved they own the account, so a specific message leaks nothing and
saves a support call.

### `AuthEventListener`

```java
@Component
class AuditListener implements AuthEventListener {

    @Override
    public void onLoginFailed(AuthUserId userId, String login, LoginFailureReason reason,
                              RequestContext context, Instant at) {
        auditTrail.record("LOGIN_FAILED", login, reason.name(), context.ipAddress());
    }

    @Override
    public void onRefreshTokenReplayDetected(AuthUserId userId, RequestContext context, Instant at) {
        alerting.critical("Refresh token replay for " + userId.value());
    }

    @Override
    public void onInvitationRedeemed(AuthUser user, Instant at) {
        users.activate(UUID.fromString(user.id().value()));   // the application owns account state
    }
}
```

Every method defaults to no-op, so implement only what you need. Listeners must not throw. The
library catches and logs, because an audit backend being down is not a reason to fail every login.

Several listeners can be registered; all are invoked.

## Replacing storage

The eight storage ports are ordinary interfaces. Turn off the JPA module and supply your own:

```yaml
spring-auth:
  jpa:
    enabled: false
```

```java
@Component
class MongoCredentialsStore implements CredentialsStore {

    public Optional<Credentials> findByUserId(AuthUserId userId) { ... }
    public Credentials save(Credentials credentials) { ... }
    public void deleteByUserId(AuthUserId userId) { ... }
}
```

Ports are `CredentialsStore`, `PasswordHistoryStore`, `MfaCredentialStore`, `RefreshTokenStore`,
`PasswordResetStore`, `InvitationStore`, `LoginHistoryStore`, `RoleStore`.

They can also be replaced one at a time: keep the JPA module and declare a single bean of the type
you want to override.

One contract worth spelling out: `RefreshTokenStore.findByTokenHash` **must return revoked and
expired rows**. Replay detection depends on still finding the token that was already rotated;
filtering them out turns a theft signal into a plain "invalid token".

## Your own endpoints

Turn the controllers off and call the services:

```yaml
spring-auth:
  web:
    enabled: false
```

```java
@RestController
@RequestMapping("/api/session")
class MyAuthController {

    private final LoginService loginService;

    @PostMapping
    MyLoginResponse login(@RequestBody MyLoginRequest request, HttpServletRequest http) {
        LoginResult result = loginService.login(
                request.email(), request.password(), RequestContexts.from(http));
        return MyLoginResponse.from(result);
    }
}
```

The filters, the security chain and the exception handler stay registered, so the hardening is
unaffected. This is the right move when the API contract is already fixed by a mobile client in the
field, or a gateway expecting a particular envelope.

## Your own security chain

```yaml
spring-auth:
  web:
    security-chain-enabled: false
```

Or simply declare a `SecurityFilterChain` bean: the library's own steps aside on
`@ConditionalOnMissingBean`.

Reuse the pieces:

```java
@Bean
SecurityFilterChain filterChain(HttpSecurity http,
                                AuthSecurityChainBuilder builder,
                                RevokedAccessTokenFilter revoked,
                                MustChangePasswordFilter mustChange) throws Exception {
    return http
            .securityMatcher("/api/**")
            .authorizeHttpRequests(reg -> reg
                    .requestMatchers(builder.publicPaths()).permitAll()
                    .requestMatchers("/api/public/**").permitAll()
                    .anyRequest().authenticated())
            .oauth2ResourceServer(oauth -> oauth
                    .jwt(jwt -> jwt.jwtAuthenticationConverter(builder.jwtAuthenticationConverter())))
            .addFilterAfter(revoked, BearerTokenAuthenticationFilter.class)
            .addFilterAfter(mustChange, BearerTokenAuthenticationFilter.class)
            .build();
}
```

Keep `builder.publicPaths()` in the permitted set. Drop it and the login endpoint requires
authentication, which nobody can obtain.

Keep `builder.jwtAuthenticationConverter()` too: it maps the permission claim **and** refuses
purpose tokens as bearer credentials. Replacing it with the default converter reopens the MFA
bypass described in the [security model](security-model.md#purpose-tokens).

## Replacing individual components

| Bean | Why you might |
|---|---|
| `PasswordEncoder` | Argon2, or matching an existing hash format during a migration |
| `Clock` | A fixed clock makes time-dependent tests deterministic |
| `RateLimiter` | A gateway-level limiter, or a different algorithm |
| `AccessTokenRevocationStore` | A store you already operate |
| `ReplayGuard` | Same |
| `JwtDecoder` | Tokens issued by an external identity provider |
| `MethodSecurityExpressionHandler` | Your own SpEL root, dropping the wildcard |

A migration from an older hash format is the common case:

```java
@Bean
PasswordEncoder passwordEncoder() {
    Map<String, PasswordEncoder> encoders = Map.of(
            "bcrypt", new BCryptPasswordEncoder(12),
            "sha256", new LegacySha256Encoder());
    DelegatingPasswordEncoder delegating = new DelegatingPasswordEncoder("bcrypt", encoders);
    delegating.setDefaultPasswordEncoderForMatches(new LegacySha256Encoder());
    return delegating;
}
```

Legacy hashes keep verifying, and every password set from then on is BCrypt.

## Using the core without Spring Boot

`spring-auth-core` depends only on `spring-security-crypto`, `nimbus-jose-jwt`, `spring-tx` and
`spring-boot` (for the properties type). The services are plain classes with constructor
injection, so you can wire them by hand if you are not on Boot.

`AuthTestFixture` in the core test sources shows the full graph being assembled manually.
