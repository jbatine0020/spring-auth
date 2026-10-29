# Configuration

Every property lives under `spring-auth`. Defaults are chosen to be safe in production rather than
convenient in development, so an empty configuration is already hardened, except for the two
secrets, which have no safe default and are covered first.

## Secrets

| Property | Default | Notes |
|---|---|---|
| `spring-auth.jwt.private-key` | *(empty)* | Base64 PKCS#8. Empty generates an ephemeral pair at boot |
| `spring-auth.jwt.public-key` | *(empty)* | Base64 X.509 SubjectPublicKeyInfo. Must be set together with the private key |
| `spring-auth.jwt.require-persistent-keys` | `false` | `true` refuses to start without persistent keys **and** a crypto master key. Set it everywhere but locally |
| `spring-auth.crypto.master-key` | *(empty)* | Base64, exactly 32 bytes. Protects TOTP seeds at rest |

Losing the crypto key makes every enrolled factor unreadable and forces every user to enrol again.
Leaking it makes them all forgeable. Treat it like a signing key.

## JWT

| Property | Default | Notes |
|---|---|---|
| `spring-auth.jwt.issuer` | `spring-auth` | `iss` claim, and the value validated on incoming tokens |
| `spring-auth.jwt.audience` | `spring-auth` | `aud` claim |
| `spring-auth.jwt.access-ttl` | `PT5M` | Short on purpose: revocation leans on expiry. Raising it widens the window in which a revoked session still works |
| `spring-auth.jwt.key-id` | *(random)* | `kid` published in the JWKS |
| `spring-auth.jwt.previous-public-key` | *(empty)* | Kept in the JWKS during a rotation |
| `spring-auth.jwt.previous-key-id` | *(empty)* | Mandatory as soon as the previous key is set |
| `spring-auth.jwt.permission-claim` | `permissions` | Rename to match an existing gateway contract |
| `spring-auth.jwt.tenant-claim` | `tenant_id` | Emitted only for users that have a tenant |
| `spring-auth.jwt.revocation-skew` | `PT30S` | Added to the access TTL when stamping a revocation, so the stamp outlives tokens issued moments before |

## Passwords

| Property | Default | Notes |
|---|---|---|
| `spring-auth.password.min-length` | `12` | Length carries most of the strength |
| `spring-auth.password.require-uppercase` | `true` | |
| `spring-auth.password.require-lowercase` | `true` | |
| `spring-auth.password.require-digit` | `true` | |
| `spring-auth.password.require-special` | `true` | Turn the four off and raise the minimum for a passphrase policy |
| `spring-auth.password.bcrypt-cost` | `12` | About 250 ms per hash. Below 10 offline cracking gets cheap; above 13 login latency shows |
| `spring-auth.password.history-size` | `5` | `0` disables the no-reuse rule |
| `spring-auth.password.max-age` | `PT0S` | Zero disables expiry. `P90D` forces a change every ninety days |
| `spring-auth.password.max-failed-attempts` | `5` | Consecutive failures before the account locks |
| `spring-auth.password.lockout-duration` | `PT15M` | How long the lock lasts |

Lock-out is per account and independent of the source address, which is what stops a distributed
attacker; the per-IP quota below is the complementary defence.

## MFA

| Property | Default | Notes |
|---|---|---|
| `spring-auth.mfa.issuer-label` | `spring-auth` | Shown in the authenticator app. Set it to your product name |
| `spring-auth.mfa.digits` | `6` | Changing it after users enrol invalidates their factors |
| `spring-auth.mfa.window` | `1` | Steps of 30 s tolerated either side. `2` helps users with drifting clocks and widens the guessing surface |
| `spring-auth.mfa.max-failed-attempts` | `5` | |
| `spring-auth.mfa.lockout-duration` | `PT15M` | |
| `spring-auth.mfa.challenge-ttl` | `PT5M` | Lifetime of the token bridging password and TOTP |
| `spring-auth.mfa.enrollment-ttl` | `PT10M` | Lifetime of the token allowing a first enrolment |
| `spring-auth.mfa.step-up-enabled` | `true` | `false` makes every `@RequiresStepUp` a no-op |
| `spring-auth.mfa.step-up-header` | `X-Mfa-Code` | |

## Sessions

| Property | Default | Notes |
|---|---|---|
| `spring-auth.session.refresh-ttl` | `P30D` | How long a session can be renewed without re-authenticating |
| `spring-auth.session.refresh-cookie-enabled` | `false` | `true` serves the refresh token as an HttpOnly cookie and withholds it from the JSON body |
| `spring-auth.session.refresh-cookie-name` | `refresh_token` | |
| `spring-auth.session.refresh-cookie-path` | `/api` | |
| `spring-auth.session.refresh-cookie-secure` | `true` | Never `false` outside a local HTTP setup |
| `spring-auth.session.refresh-cookie-same-site` | `Strict` | What keeps the cookie from becoming a CSRF vector |

Enable the cookie for browser clients: a refresh token in `localStorage` is readable by any script
that manages to run on the page, and it is long-lived by design.

## Forgotten password

| Property | Default | Notes |
|---|---|---|
| `spring-auth.password-reset.enabled` | `true` | |
| `spring-auth.password-reset.link-ttl` | `PT30M` | |
| `spring-auth.password-reset.otp-digits` | `6` | |
| `spring-auth.password-reset.max-attempts` | `5` | Wrong codes tolerated on one link before it locks |
| `spring-auth.password-reset.require-otp` | `true` | `false` runs link-only: the emailed link becomes the single factor |

## Invitations

| Property | Default | Notes |
|---|---|---|
| `spring-auth.invitation.enabled` | `true` | |
| `spring-auth.invitation.ttl` | `P7D` | The token is a credential; keep the window short |

## Rate limiting

| Property | Default | Notes |
|---|---|---|
| `spring-auth.rate-limit.enabled` | `true` | Never disable in production |
| `spring-auth.rate-limit.window` | `PT1M` | |
| `spring-auth.rate-limit.login-per-minute` | `10` | |
| `spring-auth.rate-limit.mfa-per-minute` | `10` | Covers verification and both enrolment endpoints |
| `spring-auth.rate-limit.refresh-per-minute` | `30` | Higher: legitimate clients refresh often |
| `spring-auth.rate-limit.password-reset-per-minute` | `10` | |

A QA harness generating deliberate bursts is the one legitimate reason to raise these. Raise them,
do not switch the filter off.

## Web layer

| Property | Default | Notes |
|---|---|---|
| `spring-auth.web.enabled` | `true` | `false` drops the controllers and keeps services and filters |
| `spring-auth.web.base-path` | `/api/v1/auth` | Prefix of every bundled endpoint |
| `spring-auth.web.security-chain-enabled` | `true` | `false` lets you build your own `SecurityFilterChain` |
| `spring-auth.web.jwks-enabled` | `true` | Publishes `/.well-known/jwks.json` |
| `spring-auth.web.public-paths` | *(empty)* | Extra unauthenticated paths on top of the library's own |
| `spring-auth.web.allowed-origins` | *(empty)* | Empty leaves CORS to the application. Explicit origins only, never a wildcard with credentials |
| `spring-auth.web.security-headers-enabled` | `true` | HSTS, CSP and Referrer-Policy |

Declaring your own `SecurityFilterChain` bean also stands the library's one down, without touching
any property.

## Service-to-service

| Property | Default | Notes |
|---|---|---|
| `spring-auth.internal.enabled` | `false` | |
| `spring-auth.internal.service-id` | *(empty)* | This service's identity, and the audience peers must address |
| `spring-auth.internal.token-header` | `X-Internal-Token` | |
| `spring-auth.internal.signature-header` | `X-Signature` | |
| `spring-auth.internal.token-ttl` | `PT2M` | Short: these are machine-to-machine calls |
| `spring-auth.internal.peers.<id>` | *(empty)* | Shared secret per peer, at least 32 characters |

## Toggles

| Property | Default | Notes |
|---|---|---|
| `spring-auth.enabled` | `true` | `false` disables the library entirely |
| `spring-auth.jpa.enabled` | `true` | `false` drops the JPA adapters so you can supply your own storage ports |
| `spring-auth.jpa.migrate` | `true` | `false` stops the library migrating its own schema. Apply `db/springauth/migration/V1__spring_auth_schema.sql` yourself |
| `spring-auth.redis.enabled` | `true` | `false` keeps the in-memory rate limiter, revocation store and replay guard even when Redis is available |

## A production baseline

```yaml
spring-auth:
  jwt:
    issuer: https://api.example.com
    audience: example-api
    private-key: ${SPRING_AUTH_JWT_PRIVATE_KEY}
    public-key: ${SPRING_AUTH_JWT_PUBLIC_KEY}
    key-id: ${SPRING_AUTH_JWT_KEY_ID}
    require-persistent-keys: true
  crypto:
    master-key: ${SPRING_AUTH_CRYPTO_KEY}
  password:
    max-age: P90D
  mfa:
    issuer-label: Example
  session:
    refresh-cookie-enabled: true
  web:
    allowed-origins:
      - https://app.example.com
```

With Redis on the classpath, the rate limiter, the revocation store and the replay guard become
shared automatically, which they must be behind more than one instance.
