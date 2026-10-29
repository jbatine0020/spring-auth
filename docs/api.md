# API reference

Every path below is relative to `spring-auth.web.base-path`, `/api/v1/auth` by default.

## Authentication flow

```
POST /login
  ├── status=AUTHENTICATED            → done, tokens in the response
  ├── status=MFA_CHALLENGE_REQUIRED   → POST /mfa/verify with the code
  └── status=MFA_ENROLLMENT_REQUIRED  → POST /mfa/enrollment/start
                                      → POST /mfa/enrollment/confirm
```

### `POST /login`

Public. Rate limited.

```json
{ "login": "alex@example.com", "password": "Correct-Horse-42!" }
```

```json
{
  "status": "AUTHENTICATED",
  "userId": "3f1a...",
  "login": "alex@example.com",
  "mfaStatus": "NOT_APPLICABLE",
  "mustChangePassword": false,
  "tokens": {
    "accessToken": "eyJ...",
    "refreshToken": "K3n...",
    "tokenType": "Bearer",
    "expiresIn": 300,
    "expiresAt": "2026-03-01T10:05:00Z"
  }
}
```

When a second factor applies, `tokens` is absent and `intermediateToken` carries a short-lived
token instead.

`401 LOGIN_INVALID` for every failure: unknown login, wrong password, disabled, locked. See
[security model](security-model.md#account-enumeration).

### `POST /mfa/verify`

Public. Authenticated by the challenge token in the body. Rate limited.

```json
{ "challengeToken": "eyJ...", "code": "123456" }
```

Returns the token pair. `401 MFA_INVALID_CODE`, `429 MFA_LOCKED`, `401 MFA_CHALLENGE_INVALID`.

### `POST /mfa/enrollment/start`

```json
{ "enrollmentToken": "eyJ..." }
```

```json
{
  "secret": "JBSWY3DPEHPK3PXP...",
  "otpauthUri": "otpauth://totp/Example:alex@example.com?secret=...",
  "issuer": "Example",
  "account": "alex@example.com"
}
```

The secret is returned **once**. Render `otpauthUri` as a QR code and offer `secret` as the manual
fallback. Calling it again replaces an unconfirmed enrolment, which is how "restart" works.

### `POST /mfa/enrollment/confirm`

```json
{ "enrollmentToken": "eyJ...", "code": "123456" }
```

Confirms the factor and returns the token pair.

### `POST /refresh`

Public. Authenticated by the refresh token. Rate limited.

```json
{ "refreshToken": "K3n..." }
```

Omit the body when the refresh cookie is enabled. Returns a new pair and revokes the presented
token.

`401 REFRESH_TOKEN_REPLAY` means the token was already rotated: the whole family is now revoked and
the user must authenticate again.

### `POST /logout`

Idempotent. An unknown token is not an error.

### `POST /password-reset:request`

Public. Always `202`, with the same message whether or not the account exists.

```json
{ "login": "alex@example.com" }
```

### `POST /password-reset:confirm`

```json
{ "token": "R3s...", "otp": "123456", "newPassword": "Another-Horse-77!" }
```

`400` with `PASSWORD_RESET_EXPIRED`, `PASSWORD_RESET_ALREADY_USED`, `PASSWORD_RESET_LOCKED`,
`PASSWORD_TOO_SHORT`, `PASSWORD_TOO_WEAK` or `PASSWORD_REUSED`.

### `POST /password:change`

Authenticated. The subject comes from the token, never from the request.

```json
{ "currentPassword": "...", "newPassword": "..." }
```

Revokes every session, so the client must authenticate again.

### `GET /me/login-history?limit=20`

Authenticated. Recent attempts, newest first.

```json
[
  { "successful": true, "ipAddress": "10.0.0.1", "userAgent": "Mozilla/5.0",
    "occurredAt": "2026-03-01T10:00:00Z" },
  { "successful": false, "failureReason": "BAD_PASSWORD", "ipAddress": "203.0.113.7",
    "occurredAt": "2026-03-01T09:58:12Z" }
]
```

### `GET /me/failed-attempts`

Authenticated. Failures over the last seven days, as a number.

### `POST /invitations:verify` and `POST /invitations:redeem`

Public. The token itself is the credential.

```json
{ "token": "Inv...", "password": "First-Password-42!" }
```

`verify` consumes nothing and lets the activation page render before the user types anything.
`redeem` sets the first password.

### `GET /password-policy`

Public. Human-readable summary of the active rules, for a form hint.

### `GET /.well-known/jwks.json`

Public. Public keys only. Holds two keys during a rotation.

## Administration

Each endpoint requires a permission that no role carries until you grant it.

| Endpoint | Permission |
|---|---|
| `POST /admin/users/{id}/password:set` | `auth:users:password` |
| `POST /admin/users/{id}:unlock` | `auth:users:password` |
| `POST /admin/users/{id}/mfa:reset` | `auth:users:mfa` |
| `POST /admin/users/{id}/sessions:revoke` | `auth:users:sessions` |
| `GET /admin/users/{id}/login-history` | `auth:users:sessions` |
| `POST /admin/users/{id}/invitations` | `auth:users:invite` |
| `POST /admin/users/{id}/invitations:revoke` | `auth:users:invite` |

## Roles

| Endpoint | Permission |
|---|---|
| `GET /roles` | `auth:roles:read` |
| `GET /roles/{code}` | `auth:roles:read` |
| `POST /roles` | `auth:roles:write` |
| `PUT /roles/{code}` | `auth:roles:write` |
| `PUT /roles/{code}/permissions` | `auth:roles:write` |
| `POST /roles/{code}:archive` | `auth:roles:write` |
| `POST /roles/{code}:restore` | `auth:roles:write` |

Permission updates replace the set wholesale; there is no partial update. System roles refuse every
modification.

## Error payload

```json
{
  "status": 401,
  "error": "Unauthorized",
  "code": "LOGIN_INVALID",
  "message": "Identifiants invalides",
  "path": "/api/v1/auth/login",
  "timestamp": "2026-03-01T10:00:00Z"
}
```

Validation failures add a `details` map of field to message.

Branch on `code`, never on `message`. Codes are stable across versions, messages are not.

## Error codes

| Code | Status | Meaning |
|---|---|---|
| `LOGIN_INVALID` | 401 | Any authentication failure |
| `MFA_REQUIRED` | 401 | Step-up needed, no code supplied |
| `MFA_INVALID_CODE` | 401 | Wrong, expired or replayed code |
| `MFA_LOCKED` | 429 | Too many wrong codes |
| `MFA_NOT_ENROLLED` | 409 | MFA required but no factor enrolled |
| `MFA_CHALLENGE_INVALID` | 401 | Challenge or enrolment token invalid or expired |
| `REFRESH_TOKEN_INVALID` | 401 | Unknown, expired or revoked |
| `REFRESH_TOKEN_REPLAY` | 401 | Already rotated; family revoked |
| `SESSION_REVOKED` | 401 | Token predates a revocation stamp |
| `PASSWORD_TOO_SHORT` | 400 | |
| `PASSWORD_TOO_WEAK` | 400 | Missing a required character class |
| `PASSWORD_REUSED` | 400 | Matches a recent password |
| `PASSWORD_MISMATCH` | 400 | Wrong current password |
| `PASSWORD_CHANGE_REQUIRED` | 403 | Change the password before anything else |
| `PASSWORD_RESET_INVALID` | 400 | Unknown link, or wrong code |
| `PASSWORD_RESET_EXPIRED` | 400 | |
| `PASSWORD_RESET_ALREADY_USED` | 400 | |
| `PASSWORD_RESET_LOCKED` | 400 | Too many wrong codes on this link |
| `INVITATION_INVALID` | 400 | Unknown, expired or redeemed |
| `RATE_LIMITED` | 429 | Quota exceeded; `Retry-After` is set |
| `ROLE_NOT_FOUND` | 404 | |
| `ROLE_ALREADY_EXISTS` | 409 | |
| `INTERNAL_AUTH_FAILED` | 401 | Service-to-service authentication refused |
| `VALIDATION_FAILED` | 400 | Malformed payload; see `details` |
