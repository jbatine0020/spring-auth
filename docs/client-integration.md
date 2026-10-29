# Client integration

The front-end side of every flow: what to call, what comes back, and what to show. Written for a
web or mobile client consuming the bundled endpoints.

Paths below assume the default base path `/api/v1/auth`.

## Login, all three outcomes

One endpoint, three shapes of answer. Branch on `status`, never on the presence of a field.

```
POST /login  { login, password }
   |
   +-- status = AUTHENTICATED            -> store tokens, go to the app
   +-- status = MFA_CHALLENGE_REQUIRED   -> ask for a 6-digit code
   +-- status = MFA_ENROLLMENT_REQUIRED  -> show the QR enrolment screen
```

```js
const result = await post('/api/v1/auth/login', { login, password });

switch (result.status) {
  case 'AUTHENTICATED':
    saveTokens(result.tokens);
    return result.mustChangePassword ? goTo('/change-password') : goTo('/');
  case 'MFA_CHALLENGE_REQUIRED':
    return goTo('/mfa/verify', { challengeToken: result.intermediateToken });
  case 'MFA_ENROLLMENT_REQUIRED':
    return goTo('/mfa/enrol', { enrollmentToken: result.intermediateToken });
}
```

`intermediateToken` is short-lived: five minutes for a challenge, ten for an enrolment. Keep it in
memory for the duration of the screen, never in storage. If it expires the API answers
`MFA_CHALLENGE_INVALID` and the user restarts from the login form.

**On failure** the answer is always `401` with `code: "LOGIN_INVALID"`, whatever went wrong. Show
one message. Do not try to distinguish cases: the API deliberately does not tell you, because
telling the client would tell an attacker.

**`429 RATE_LIMITED`** carries a `Retry-After` header and a `retryAfterSeconds`-style delay in the
message. Show the delay and disable the submit button until it elapses.

## MFA enrolment

```js
// 1. Get the secret and the QR payload
const enrolment = await post('/api/v1/auth/mfa/enrollment/start', { enrollmentToken });

// 2. Render enrolment.otpauthUri as a QR code, and show enrolment.secret as the manual fallback
renderQrCode(enrolment.otpauthUri);
showManualEntry(enrolment.secret);

// 3. The user types the first code from their authenticator
const tokens = await post('/api/v1/auth/mfa/enrollment/confirm', { enrollmentToken, code });
saveTokens(tokens);
```

The secret is returned **once**. There is no endpoint to read it back, by design. If the user
leaves the screen before confirming, they log in again and start a fresh enrolment; the previous
unconfirmed secret is replaced.

Always show the manual entry string next to the QR code. Users on a desktop authenticator, or with
a camera that will not focus, need it.

## MFA verification

```js
const tokens = await post('/api/v1/auth/mfa/verify', { challengeToken, code });
```

| Response | Meaning | What to show |
|---|---|---|
| `401 MFA_INVALID_CODE` | Wrong, expired or already used code | Let them retry, silently |
| `429 MFA_LOCKED` | Too many wrong codes | Tell them to wait, offer support contact |
| `401 MFA_CHALLENGE_INVALID` | The challenge token expired | Send them back to the login form |

A code is single use. If the user submits the same code twice, for instance by double-clicking, the
second attempt fails as a replay. Disable the button on submit.

## Token handling

**Access token.** Send it as `Authorization: Bearer <token>` on every call. It lives five minutes.

**Refresh token.** Two modes, chosen by the server.

*Body mode (default).* `tokens.refreshToken` is in the response and the client stores it. On a
browser, that means `localStorage` or `sessionStorage`, both readable by any script that manages to
run on the page.

*Cookie mode (`spring-auth.session.refresh-cookie-enabled: true`).* The refresh token is set as an
HttpOnly cookie and `tokens.refreshToken` is absent from the body. JavaScript cannot read it, so an
XSS cannot steal it. Call `/refresh` with `credentials: 'include'` and an empty body. Prefer this
mode for browser clients.

## Refreshing

Refresh on `401`, then replay the original request once:

```js
async function call(path, options) {
  let response = await fetch(path, withAuth(options));
  if (response.status === 401) {
    await refresh();
    response = await fetch(path, withAuth(options));
  }
  return response;
}
```

**Serialise the refresh.** Several requests failing at once must not each trigger their own
refresh: the first rotation invalidates the token the others are about to present, and the second
call is then read as a replay, which burns the whole family and logs the user out. Keep a single
in-flight refresh promise and let the others await it.

```js
let inFlight = null;

function refresh() {
  if (!inFlight) {
    inFlight = post('/api/v1/auth/refresh', { refreshToken: load() })
      .then(saveTokens)
      .finally(() => { inFlight = null; });
  }
  return inFlight;
}
```

**`REFRESH_TOKEN_REPLAY`** means the server detected two holders of the same token and closed every
session in the family. Clear local state and send the user to the login form with a message about
the session being closed for security. Do not retry.

## Forced password change

When `mustChangePassword` is true, or any call answers `403 PASSWORD_CHANGE_REQUIRED`, the only
reachable endpoints are the password change and logout. The server enforces it, so there is no way
to skip the screen by editing the client.

```js
await post('/api/v1/auth/password:change', { currentPassword, newPassword });
// every session is now closed: send the user back to the login form
```

Fetch `/password-policy` to show the rules next to the field rather than hard-coding them.

## Forgotten password

```js
await post('/api/v1/auth/password-reset:request', { login });
// always 202, whether or not the account exists
```

Show the same confirmation either way. The API will not tell you whether the address is registered,
and neither should the interface.

The user then receives a link by email and, when the deployment requires it, a code by SMS. The
activation page reads the token from the URL:

```js
await post('/api/v1/auth/password-reset:confirm', { token, otp, newPassword });
```

| Response | What to show |
|---|---|
| `PASSWORD_RESET_EXPIRED` | The link expired, offer to request a new one |
| `PASSWORD_RESET_ALREADY_USED` | Already used, offer to request a new one |
| `PASSWORD_RESET_LOCKED` | Too many wrong codes, they must request a new link |
| `PASSWORD_RESET_INVALID` | Wrong code, let them retry |
| `PASSWORD_TOO_SHORT`, `PASSWORD_TOO_WEAK`, `PASSWORD_REUSED` | Show the policy, keep the link usable |

A rejected password does not consume the link, so the user can correct it and submit again.

## Invitation

```js
// On page load, before the user types anything
const account = await post('/api/v1/auth/invitations:verify', { token });
// account.message holds the login the invitation was issued for

// After they choose a password
await post('/api/v1/auth/invitations:redeem', { token, password });
```

`verify` consumes nothing, so the page can render, or show an expired-link message, without burning
the invitation.

## Step-up on a sensitive action

Endpoints annotated `@RequiresStepUp` need a current TOTP code in a header:

```js
const response = await fetch('/api/transfers', {
  method: 'POST',
  headers: { ...auth(), 'X-Mfa-Code': code },
  body: JSON.stringify(transfer),
});
```

Call it without the header first: a `401 MFA_REQUIRED` is the signal to prompt for a code. That
avoids asking for a code on an action that turns out not to need one.

One action, one code. A code consumed by a step-up cannot be reused for the next action inside the
same thirty-second window, so prompt again rather than caching it.

## Logout

```js
await post('/api/v1/auth/logout', { refreshToken: load() });
clearLocalState();
```

Idempotent, so a double click is harmless. The access token stays cryptographically valid until it
expires, which is why the server also records a revocation stamp: subsequent calls with it are
refused with `SESSION_REVOKED`.

## Recent activity

```js
const attempts = await get('/api/v1/auth/me/login-history?limit=20');
```

Worth surfacing in the account settings. A user recognising an unfamiliar address or a burst of
failures is often the first real signal of a compromise.

## Error handling in one place

Every error shares the same envelope, so one interceptor covers the API:

```js
function messageFor(error) {
  switch (error.code) {
    case 'LOGIN_INVALID':            return "Identifiants invalides";
    case 'RATE_LIMITED':             return "Trop de tentatives, réessayez dans un instant";
    case 'MFA_INVALID_CODE':         return "Code incorrect";
    case 'MFA_LOCKED':               return "Trop de tentatives, patientez quelques minutes";
    case 'REFRESH_TOKEN_REPLAY':     return "Session fermée pour raison de sécurité";
    case 'PASSWORD_CHANGE_REQUIRED': return "Changez votre mot de passe pour continuer";
    default:                         return error.message;
  }
}
```

Branch on `code`. It is stable across versions; `message` is not, and is French by default.
