# Architecture

How the library is put together, and why the seams are where they are.

## The central decision: the library does not own your users

Every application models users differently. Companies, branches, agents, customers, external
partners. A library that shipped its own user table would force every consumer into a
synchronisation problem: two records for the same person, drifting apart on status, email and
roles.

So the split is drawn one level lower. The library owns what is genuinely generic:

| Owned by the library | Owned by your application |
|---|---|
| Password hashes and lock-out state | The user record itself |
| TOTP factors | Identity, profile, tenant membership |
| Refresh tokens and sessions | Account lifecycle (create, disable, delete) |
| Password reset requests | Which users exist and what status they hold |
| Invitations | Role assignment |
| Roles and their permissions | What a permission means |
| Login history | |

The bridge is one interface, `AuthUserDirectory`, through which the application supplies a
read-only projection called `AuthUser`. Everything else follows from that.

## Modules and the dependency rule

```
spring-auth-spring-boot-starter
        |
        +---> spring-auth-web  ---> spring-auth-core
        |                              ^
        +---> spring-auth-jpa  --------+
```

Dependencies point inwards only. `spring-auth-core` knows nothing about servlets, JPA or Spring
Boot auto-configuration.

**`spring-auth-core`** holds the domain model, the crypto, JWT issuance, the services and both
sets of interfaces. Its only dependencies are `spring-security-crypto` (for `PasswordEncoder`),
`nimbus-jose-jwt`, `spring-tx` (authentication needs precise rollback semantics) and `spring-boot`
(for the properties type). No stereotype annotations: the services are plain classes with
constructor injection, and the starter wires them.

**`spring-auth-jpa`** implements the storage ports against JPA and ships the Flyway migration.
Written against `EntityManager` rather than Spring Data repositories, because a library that
declared its own repositories would have to enable repository scanning, which switches off the
auto-configured scan of the consuming application and silently breaks its repositories.

**`spring-auth-web`** holds the controllers, the filters, the security chain builder, the step-up
interceptor and the service-to-service pieces. Every class is instantiable on its own, so an
application can reuse a filter without taking the controllers.

**`spring-auth-spring-boot-starter`** is the only module with auto-configuration. It also carries
the optional adapters: Redis-backed rate limiting, revocation and replay detection, plus the
dedicated Flyway instance.

## Two kinds of interface

The distinction matters when you read the code.

**SPI, in `core.spi`.** Interfaces the *application* implements so the library can reach into it:
`AuthUserDirectory`, `AuthMessenger`, `AuthEventListener`, `LoginGuard`.

**Ports, in `core.port`.** Interfaces the *library* needs implemented so it can persist:
`CredentialsStore`, `MfaCredentialStore`, `RefreshTokenStore` and five others. Satisfied out of the
box by `spring-auth-jpa`, replaceable one at a time.

Rate limiting, replay detection and access-token revocation are ports too, with in-memory defaults
and Redis alternatives.

## Where the domain lives

Aggregates in `core.model` are plain final classes with private constructors, static factories and
named mutation methods. No framework annotation, no setter. Persistence adapters map to and from
them explicitly rather than through field access, so the invariants hold and the schema can evolve
without leaking into the model.

The invariants that live in the aggregates rather than the services:

- `Credentials` locks at the threshold, refuses to count while locked, resets on success
- `MfaCredential` refuses a counter that is not strictly newer, and confirms only on first success
- `RefreshToken` cannot be rotated twice, and revocation is idempotent
- `PasswordResetRequest` refuses a second use, and locks after the allowed attempts
- `Role` refuses every modification when it is a system role

Anything needing a `PasswordEncoder` or a `Clock` lives in the service layer instead, since the
model has no dependencies.

## Request path

```
AuthRateLimitFilter                 per-address quota, before any BCrypt work
  InternalServiceAuthFilter         peer identity, when service-to-service is on
    WebhookSignatureFilter          body HMAC, after the peer is known
      BearerTokenAuthenticationFilter    Spring Security validates the JWT
        RevokedAccessTokenFilter    refuses tokens issued before a revocation stamp
        MustChangePasswordFilter    blocks everything but the change and logout
          StepUpInterceptor         @RequiresStepUp, before the handler runs
            controller
```

The ordering is deliberate at three points. Rate limiting runs first so a flood costs no hashing.
Signature verification runs after peer identification because the signing key is the secret of the
peer that just proved its identity. Step-up runs in `preHandle` so a wrong code leaves no business
write behind.

## Token model

Two credentials with opposite designs, on purpose.

**Access tokens** are RS256 JWTs, self-contained and short-lived (five minutes). Authorising a
request costs no database lookup, and the expiry is the main bound on a compromised one. Public
keys are published as a JWKS so a gateway or a peer can validate without a shared secret.

**Refresh tokens** are opaque 256-bit random secrets, stored as a SHA-256 digest, long-lived and
revocable. They rotate on every use and belong to a family that is burnt on replay.

Between the two sit **purpose tokens**, short-lived JWTs carrying a `purpose` claim, used between
the password step and the MFA step. The resource server refuses any bearer token carrying that
claim, which is what stops a challenge token from acting as an access token.

## Failure philosophy

Three rules explain most of the error handling.

**The authentication path leaks nothing.** Every failure answers the same way. Detail goes to the
login history.

**Audit failures never fail the request.** A listener that throws, or an unreachable history table,
is logged and swallowed. An audit backend being down is not a reason to lock every user out.

**Counters commit even when the call throws.** A wrong password increments the failure counter and
then raises. Rolling that back would mean lock-out never triggers.

## Extension points, in order of reach

| You want to | Do this |
|---|---|
| Add an application rule to login | Implement `LoginGuard` |
| React to authentication events | Implement `AuthEventListener` |
| Change one storage backend | Declare one bean implementing that port |
| Change the API contract | `spring-auth.web.enabled: false`, call the services |
| Change the security chain | Declare your own `SecurityFilterChain` bean |
| Replace the HTTP layer entirely | Depend on `spring-auth-core` alone |

See [extending](extending.md) for the code.
