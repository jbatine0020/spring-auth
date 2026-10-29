# Migrating an existing application

Adopting the library when authentication already exists. The green-field path is in
[getting started](getting-started.md); this covers the awkward parts of replacing something live.

## What has to move, and what does not

Your user table stays exactly as it is. What moves is the material around it:

| Currently in your schema | Moves to |
|---|---|
| Password hash, failed attempts, locked until | `auth_credentials` |
| MFA secret, counter | `auth_mfa_credentials` |
| Refresh tokens or server sessions | `auth_refresh_tokens` |
| Password reset tokens | `auth_password_resets` |
| Invitation tokens | `auth_invitations` |
| Login history | `auth_login_attempts` |
| Roles and permissions | `auth_roles`, `auth_role_permissions` |

Columns in your user table backing those concerns become dead once the migration completes. Drop
them in a later release, not the same one, so a rollback stays possible.

## Keeping existing passwords working

The common blocker. Your users must not all be forced through a reset.

**If you already use BCrypt**, nothing to do. Copy the hashes into `auth_credentials` and they
verify as they are, whatever cost they were produced with.

**If you use something else**, register a `DelegatingPasswordEncoder`. Legacy hashes keep
verifying, and every password set from then on is BCrypt:

```java
@Bean
PasswordEncoder passwordEncoder() {
    Map<String, PasswordEncoder> encoders = Map.of(
            "bcrypt", new BCryptPasswordEncoder(12),
            "sha256", new LegacySha256Encoder());
    DelegatingPasswordEncoder delegating = new DelegatingPasswordEncoder("bcrypt", encoders);
    // Hashes carrying no {id} prefix are the legacy ones.
    delegating.setDefaultPasswordEncoderForMatches(new LegacySha256Encoder());
    return delegating;
}
```

Passwords upgrade opportunistically as users change them. To force the pace, set
`spring-auth.password.max-age` so they age out on a schedule of your choosing.

## Copying the data

One migration in your own Flyway, running after the library's tables exist. The library migrates on
its own instance at startup, so in practice you write this as a repeatable or versioned migration
that assumes the tables are there, or as a one-off job at deployment.

```sql
INSERT INTO auth_credentials (
    id, user_id, password_hash, password_set_at,
    failed_attempts, locked_until, must_change_password, updated_at)
SELECT gen_random_uuid(),
       u.id::text,
       u.password_hash,
       COALESCE(u.password_changed_at, now()),
       COALESCE(u.failed_login_count, 0),
       u.locked_until,
       COALESCE(u.must_change_password, false),
       now()
FROM users u
WHERE u.password_hash IS NOT NULL;
```

Two details worth getting right.

`user_id` is a 64-character text column holding whatever identifier your `AuthUserDirectory`
returns. Cast consistently: if the directory returns `AuthUserId.of(entity.getId())` on a UUID, the
copy must write the same textual form.

`password_set_at` drives expiry. Defaulting it to `now()` gives every user a fresh clock, which is
usually what you want on the day of the migration.

## Existing MFA secrets

Only portable if they are TOTP secrets in base32 and you can decrypt them. The library stores them
encrypted with AES-GCM under `spring-auth.crypto.master-key`, so a copy means decrypting with the
old scheme and re-encrypting with `SecretCipher`:

```java
mfaSecrets.forEach(row -> {
    String base32 = legacyCipher.decrypt(row.getSecret());
    MfaCredential credential = MfaCredential.enroll(
            AuthUserId.of(row.getUserId()), secretCipher.encrypt(base32), Instant.now());
    credential.recordSuccessfulVerification(row.getLastCounter(), Instant.now());
    mfaCredentialStore.save(credential);
});
```

`recordSuccessfulVerification` is what marks the factor confirmed and carries over the replay
counter. Without it every user would be asked to enrol again.

If the secrets are not portable, do not fake it. Leave the table empty, let the users enrol on next
login, and tell them in advance.

## Sessions

Do not migrate them. Whatever session or refresh token your old system issued, the shape does not
match and the cryptographic properties do not carry over.

Plan for everyone to re-authenticate at cutover. Announce it, and pick a moment when a forced
re-login is cheapest.

## Roles and permissions

Seed at startup, so the set is reproducible across environments and reviewable in code:

```java
@Component
class RoleSeeder implements ApplicationRunner {

    private final RoleService roles;

    public void run(ApplicationArguments args) {
        roles.seedSystemRole("ADMIN", "Administrator", null,
                Set.of("auth:users:password", "auth:users:mfa", "auth:roles:read",
                       "auth:roles:write", "orders:read", "orders:write"));
        roles.seedSystemRole("SUPPORT", "Support", null,
                Set.of("auth:users:sessions", "orders:read"));
    }
}
```

`seedSystemRole` is idempotent and marks the role protected, so the administration API refuses to
modify or archive it. That is what stops an operator from emptying the role their own access
depends on.

Your `AuthUserDirectory` then returns the role codes each user holds, and the library expands them
into token permissions.

## Keeping your own API contract

A mobile client in the field, or a gateway expecting a particular envelope, means you cannot change
the login response shape. Turn the controllers off and keep the services:

```yaml
spring-auth:
  web:
    enabled: false
```

```java
@RestController
@RequestMapping("/api/session")
class LegacyAuthController {

    private final LoginService loginService;

    @PostMapping
    LegacyResponse login(@RequestBody LegacyRequest request, HttpServletRequest http) {
        LoginResult result = loginService.login(
                request.username(), request.password(), RequestContexts.from(http));
        return LegacyResponse.from(result);   // your envelope, your field names
    }
}
```

The filters, the security chain and the exception handler stay registered, so the hardening applies
either way. See [extending](extending.md).

## Application rules that lived in the old login

Portal restrictions, suspended organisations, country checks. They belong in a `LoginGuard`, which
runs after the password check and before any token is issued:

```java
@Component
class TenantStatusGuard implements LoginGuard {

    @Override
    public void check(AuthUser user, RequestContext context) {
        if (user.tenantId() != null && !companies.isActive(user.tenantId())) {
            throw new CompanySuspendedException();   // extends AuthException
        }
    }
}
```

Resist the temptation to put these checks in `AuthUserDirectory` by returning `DISABLED`. That
collapses distinct situations into one, and the user gets a generic failure where a specific
message would have saved a support call.

## Suggested cutover

1. **Release A.** Add the library, keep the old authentication live and unused by nobody yet.
   Tables are created, nothing changes for users.
2. **Backfill.** Copy credentials, roles and MFA secrets. Verify on a restored production dump that
   a sample of users can authenticate through the new path.
3. **Release B.** Switch the login endpoint to the library. Sessions are invalidated, everyone
   re-authenticates once.
4. **Watch.** Failed logins, lock-outs, support volume. The first hour tells you whether the
   backfill was right.
5. **Release C.** Drop the dead columns from your user table, once a rollback is no longer on the
   table.

Rolling back is only free between steps 1 and 2. After the switch, users have set passwords through
the library and rolling back loses them.

## Checks before the switch

- [ ] A sample of production hashes verifies through the configured `PasswordEncoder`
- [ ] `AuthUserDirectory` returns the same identifier form as the backfilled `user_id`
- [ ] Status mapping is right: only `ACTIVE` can authenticate
- [ ] Roles seeded, and a user carrying each one gets the expected permissions in their token
- [ ] `AuthMessenger` wired, with reset and invitation delivery tested end to end
- [ ] Both secrets configured, and `require-persistent-keys: true`
- [ ] The startup report is clean
