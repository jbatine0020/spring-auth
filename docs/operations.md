# Operations

Running spring-auth in production: key rotation, housekeeping, scaling, and what to watch.

## Before going live

- [ ] `spring-auth.jwt.require-persistent-keys: true`
- [ ] `jwt.private-key`, `jwt.public-key` and `crypto.master-key` supplied from a secret manager
- [ ] `crypto.master-key` backed up. Losing it invalidates every enrolled MFA factor permanently
- [ ] Rate limiting on
- [ ] An `AuthMessenger` implemented and tested end to end
- [ ] Redis available if more than one instance runs
- [ ] `web.allowed-origins` listing explicit origins, no wildcard
- [ ] Housekeeping jobs scheduled (below)
- [ ] `flyway-core` on the classpath, or `spring-auth.jpa.migrate: false` with the schema applied
      by your own pipeline
- [ ] The startup report reads *"started with a hardened configuration"*

## Rotating the signing key

Zero downtime, three deployments.

**1. Publish the new key alongside the old one.** Keep signing with the current key while both
appear in the JWKS:

```yaml
spring-auth:
  jwt:
    private-key: ${CURRENT_PRIVATE}
    public-key: ${CURRENT_PUBLIC}
    key-id: kid-2025
    previous-public-key: ${OLDER_PUBLIC}
    previous-key-id: kid-2024
```

**2. Switch the signing key.** The former current key becomes the previous one:

```yaml
spring-auth:
  jwt:
    private-key: ${NEW_PRIVATE}
    public-key: ${NEW_PUBLIC}
    key-id: kid-2026
    previous-public-key: ${CURRENT_PUBLIC}
    previous-key-id: kid-2025
```

Tokens signed before the switch keep validating until they expire, which is minutes given the default
access TTL.

**3. Drop the previous key**, once the longest access TTL has elapsed. One access TTL plus a margin
is enough; there is no need to wait for refresh tokens, since a refresh mints a token with the new
key.

Consumers that cache the JWKS must refresh it between steps 1 and 2. A gateway caching for an hour
needs an hour between those deployments.

## Rotating the crypto master key

There is no online rotation. The key protects TOTP seeds, and re-encrypting them requires reading
every seed with the old key and writing it back with the new one.

If you must:

1. Deploy with the new key while keeping the old one available to your own code.
2. Run a one-off job reading `auth_mfa_credentials.encrypted_secret` with the old cipher and
   rewriting it with the new one.
3. Remove the old key.

Simpler alternative when the population is small: reset every factor
(`POST /admin/users/{id}/mfa:reset`) and let users enrol again. Disruptive, but with no migration
job to get wrong.

## Housekeeping

The library never deletes on its own. Retention is a compliance decision, not a library one.
Schedule these:

```java
@Component
class AuthHousekeeping {

    private final RefreshTokenStore refreshTokens;
    private final PasswordResetStore passwordResets;
    private final InvitationStore invitations;
    private final LoginHistoryService loginHistory;

    /** Expired refresh tokens: keep them a while as replay evidence, then drop them. */
    @Scheduled(cron = "0 0 3 * * *")
    @Transactional
    public void purgeExpiredTokens() {
        Instant cutoff = Instant.now().minus(Duration.ofDays(7));
        refreshTokens.deleteExpiredBefore(cutoff);
        passwordResets.deleteExpiredBefore(cutoff);
        invitations.deleteExpiredBefore(cutoff);
    }

    /** Login history grows fastest; pick the window your retention policy allows. */
    @Scheduled(cron = "0 30 3 * * *")
    public void purgeLoginHistory() {
        loginHistory.purgeOlderThan(Duration.ofDays(365));
    }
}
```

`auth_login_attempts` is the table to watch: one row per attempt, successful or not, including
attempts against unknown logins. A credential-stuffing campaign inflates it quickly.

## Running several instances

Three concerns break when each replica keeps its own state:

| Concern | With per-instance state | Fix |
|---|---|---|
| Rate limiting | N replicas means N times the configured quota | Redis |
| Token revocation | A logout only applies to the instance that handled it | Redis |
| Replay detection | A token replayed against another instance goes through | Redis |

Adding Spring Data Redis and a `StringRedisTemplate` is enough. The starter swaps the three
automatically and the startup report stops warning about them.

Refresh tokens, credentials and factors live in the database, so they are shared already.

## What to monitor

| Signal | Source | Why |
|---|---|---|
| Failed logins per minute | `onLoginFailed` | A spike is credential stuffing |
| Accounts locked per hour | `onAccountLocked` | A targeted attack, or a broken client retrying |
| **Refresh token replays** | `onRefreshTokenReplayDetected` | A token leaked. Alert on any occurrence |
| MFA verification failures | `onMfaVerificationFailed` | Code guessing, or clock drift on a device |
| Password resets requested | `onPasswordResetRequested` | A surge suggests account takeover attempts |
| `429` rate on `/login` | Access log | The limiter is working, or is too tight |

The replay signal is the one to page on. Everything else is noise until it is a trend; a replay is
a single event that means a secret escaped.

## Schema changes

The library migrates itself on a dedicated Flyway instance: location
`classpath:db/springauth/migration`, history table `flyway_schema_history_springauth`. It never
shares your history, so its versions and yours can never collide.

Upgrading the library may bring a `V2`. It applies on the next start, before the entity manager is
built. Review the SQL in the jar first when the database is managed by a separate team, and if it
is, set `spring-auth.jpa.migrate: false` and hand the file over.

`baselineOnMigrate` is on: introducing the library into a database that already exists is a normal
case, and the empty history is not a gap to be flagged.

## Troubleshooting

**Every endpoint returns 404.** The controllers were not registered. Check that an
`AuthUserDirectory` bean exists. Without it the services and the controllers are skipped. Also
check `spring-auth.web.enabled`.

**`401` on a public endpoint.** A stale `Authorization` header. The library's bearer resolver
ignores the header on public paths, but a custom security chain that dropped
`builder.publicPaths()` reintroduces the problem.

**Every token invalid after a restart.** No persistent JWT key configured. See the boot warning.

**`Failed to decrypt` on MFA verification.** The crypto master key changed. Enrolled factors are
unreadable; reset them.

**Lock-out never triggers.** The failure counter is being rolled back. This happens when the login
service is wrapped in an outer transaction that rolls back on `AuthException`. The library's own
methods carry `noRollbackFor`; an outer transaction of yours must do the same.

**Users must change their password on every login.** `password.max-age` is set lower than intended,
or a reset left the flag on. `must_change_password` is cleared by a self-service change, not by an
administrative set.

**Slow logins.** BCrypt cost. 12 is about 250 ms by design; anything higher shows up immediately at
volume.
