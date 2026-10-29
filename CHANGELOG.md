# Changelog

Versions follow [semantic versioning](https://semver.org). For this library that means:

- **major** for a change to the SPI, to a storage port, or to an error code, since all three are
  contracts consumers build on
- **minor** for a new capability, a new property, or a new migration
- **patch** for a fix that changes no contract

## 1.0.0-SNAPSHOT

Required password changes now have a dedicated authenticated `POST /password:first-change` endpoint accepting only the new password. The JWT must carry `must_change_password`, and the service independently checks the current credentials. Password policy, no-reuse checks and session revocation are preserved; ordinary self-service changes still require the current password.

Initial reusable-library workspace. Module names, packages, configuration keys, cookie defaults and migration history names use the neutral library namespace. The application-specific identity adapter is not included. Business-role seeding is left to consuming applications.

PostgreSQL migrations and sequence access are implemented. Refresh rotation and MFA verification now use row locks; refresh replay commits family revocation before returning an authentication error. Custom stores must implement the locking lookup methods added to their ports.

The capabilities below describe the implementation; this snapshot is not a published release.

### Authentication

- Password login with a configurable policy, BCrypt at a chosen cost, no-reuse history and expiry
- Per-account brute-force lock-out, independent of the source address
- Account-enumeration resistance: every failure answers identically, and unknown accounts are
  timing-equalised against a constant hash computed at startup
- `LoginGuard` for application rules that must run after the password check and before any token
  is issued

### Multi-factor

- TOTP (RFC 6238) with seeds encrypted at rest under AES-256-GCM
- Replay-proof verification through a stored counter, and per-account lock-out
- Two-phase enrolment, so an unconfirmed factor never locks a user out
- Step-up confirmation through `@RequiresStepUp` and the `X-Mfa-Code` header

### Sessions

- RS256 access tokens with a published JWKS and zero-downtime key rotation
- Purpose tokens for the intermediate authentication steps, refused as bearer credentials
- Opaque refresh tokens with rotation and family invalidation on replay
- Server-side revocation stamps, checked on every request

### Account flows

- Forgotten password over an emailed link plus an SMS code, single use and attempt-locked
- Single-use invitation links with a bounded lifetime
- Forced password change enforced server-side, not only signalled to the front-end

### Authorisation

- Role and permission administration, with protected system roles
- Permissions resolved into the access token at issuance
- Wildcard break-glass permission honoured by `@PreAuthorize`

### Service-to-service

- Short-lived HS256 tokens with audience pinning and one-shot identifiers
- HMAC-SHA256 body signatures for webhooks, verified in constant time

### Infrastructure

- Auto-configuration for core, JPA, web and the optional Redis adapters
- A dedicated Flyway instance with its own history table, so the library's migrations never collide
  with the application's
- Rate limiting, revocation and replay detection shared across instances when Redis is present
- A startup report naming the settings that are safe in development and risky in production

### Known limitations

- PostgreSQL is the supported storage target for this initial snapshot. The 13 migrations, profile sequence and binary mappings are covered by real-database tests; this is not an in-place conversion path for databases on another engine.
- Rotating the crypto master key has no online path. Either re-encrypt the TOTP seeds with a
  one-off job, or reset the factors and have users enrol again.
- No federated identity. The library authenticates against its own credentials; SAML or social
  login is a different integration.
- Rotating a service-to-service shared secret has no dual-secret window, so it needs a short
  maintenance window.
