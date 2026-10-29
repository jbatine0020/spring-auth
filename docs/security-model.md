# Security model

What each mechanism defends against, and what it costs. Read this before changing a default. Most
of them exist because of a specific attack.

## Account enumeration

**The attack.** An unauthenticated endpoint that answers differently for "no such account" and
"wrong password" is a free membership oracle. Feed it a breach list and you learn which addresses
are registered, which is the first step of a targeted phishing or credential-stuffing campaign.

**What the library does.** Unknown login, wrong password, disabled account, unredeemed invitation
and locked account all produce the same `LOGIN_INVALID`, the same message and the same HTTP 401.
The precise reason goes to the login history, where only operators see it.

The forgotten-password endpoint answers `202` with the same wording whether or not the address
exists, for the same reason.

**Timing.** A missing account would answer in a millisecond while a real one spends ~250 ms in
BCrypt, and that gap alone is a reliable oracle. Every early exit therefore runs one throwaway hash
comparison against a constant generated at startup with the configured cost.

**The cost.** Support cannot tell a user "this address is not registered" from the API response.
That is the intended trade.

## Brute force

Two independent barriers, because either alone is bypassable.

**Per-account lock-out.** Five consecutive failures freeze the account for fifteen minutes. Stops
an attacker grinding one account, whatever addresses they use.

**Per-address rate limiting.** Ten login attempts a minute per address. Stops one host trying many
accounts, which lock-out alone would not.

A distributed attacker with many addresses is contained by the first; a single host trying a
password list against many accounts is contained by the second.

**The failure counter must survive the exception.** A wrong password increments the counter and
then throws. Rolling that back on the exception (the default in Spring) would erase the
increment and lock-out would never trigger, no matter how many attempts were made. Hence
`@Transactional(noRollbackFor = AuthException.class)` on the login and MFA services. This is the
kind of bug that passes every unit test and never fires in production.

## Password storage

BCrypt at cost 12, roughly 250 ms per hash. Below 10 an offline attacker gets too much throughput
against a leaked table; above 13 login latency becomes noticeable.

No-reuse history keeps the last hashes and refuses a password that matches one of them. The
history is bounded. Beyond the comparison window, old hashes protect nothing and only add
crackable material to a leaked table.

## TOTP second factor

**Seeds at rest.** Encrypted with AES-256-GCM, never stored in clear. GCM is authenticated, so a
tampered ciphertext fails loudly instead of decrypting to garbage. A fresh 12-byte IV per
encryption is what keeps GCM safe.

**Replay.** A TOTP code stays mathematically valid for its whole 30-second step, so anyone who
observes one can reuse it inside that window. The credential therefore stores the last accepted
counter and refuses anything not strictly newer. One code, one use.

**Guessing.** Six digits is a million combinations, and the holder of a challenge token can try
them from anywhere. Lock-out is per account, not per address, precisely because the address is not
a constraint for the attacker.

**Two-phase enrolment.** A seed is stored unconfirmed, and only a first valid code makes the factor
count. Without that, a user who scanned the QR code into the wrong app, or never scanned it at all,
would be locked out of their own account at the next login.

**Comparison is constant-time**, so a wrong code leaks nothing about how wrong it was.

## Purpose tokens

Between the password step and the TOTP step the client holds a short-lived token. It shares issuer,
audience and signing key with an access token, which makes it dangerous: without a distinguishing
check it satisfies `anyRequest().authenticated()` and reaches every endpoint that is not separately
annotated, a complete MFA bypass for anyone who knows the password.

Two defences. Purpose tokens carry a `purpose` claim, and the resource server refuses any bearer
token that has one. And the verifier requires the *exact* purpose, so an enrolment token cannot be
used to pass verification.

## Sessions

**Access tokens are short.** Five minutes by default. They are self-contained, so the expiry is the
main limit on how long a compromised one is useful.

**Refresh tokens rotate.** Each refresh mints a new token and revokes the presented one, so a
captured token is only useful until the real client refreshes.

**Families invalidate.** Presenting an already-revoked token means two parties hold the same
secret. The whole family is revoked, logging out attacker and victim alike. The victim
re-authenticates (an inconvenience) and the compromise surfaces instead of persisting silently.

**Revocation stamps.** A signed JWT cannot be withdrawn, so logout, password change and
administrative lockout record an instant per user; tokens issued before it are refused. The record
only has to outlive one access TTL, so an expiring store fits.

**Storage.** Refresh tokens are 256-bit random secrets, never JWTs, and only their SHA-256 digest
is stored. An unsalted digest is right here: the input already has 256 bits of entropy, so there
is no dictionary to run and no need for a slow KDF, and salting would break lookup by hash.

**Fail-open on the revocation check.** If the revocation store is unreachable, requests are let
through. The alternative locks every authenticated user out because a cache is down. The window is
bounded by the access TTL, and the refresh tokens are already revoked in the database, so the
session cannot be renewed either way.

## Forgotten password

Two independent factors: a 256-bit token in an emailed link, and a numeric code sent by SMS.
Neither a compromised mailbox nor a stolen phone is enough alone.

The link is single-use, expires in thirty minutes, and locks after five wrong codes. Without that
last rule, six digits would be brute-forceable for the whole life of the link. The OTP is stored
through the password encoder rather than a bare digest, because its search space is small enough to
sweep offline.

The new password is validated *before* the link is consumed, so a rejected password does not cost
the user their only attempt.

Completing a reset revokes every session: leaving the attacker's refresh token alive would defeat
the point.

## Forced password change

When an administrator resets a password or one ages out, the access token carries
`must_change_password`. Left as a front-end hint, the flag is trivially ignored: the user, or an
attacker holding a temporary password, skips the redirect and keeps working. A filter therefore
refuses every request except the password change itself, logout and CORS preflights.

## Service-to-service

Symmetric HS256 is the right trade here: both ends are trusted infrastructure sharing a secret,
there is no third party to verify without the ability to sign, and it avoids distributing keys for
calls that live two minutes.

Three checks make a captured token useless. A short expiry. An audience pinned to the callee, so
a token addressed to service A cannot be forwarded to service B sharing the same peer secret. And
a one-shot `jti`. Signature and expiry alone leave a replay window open to anyone who observes one
call.

A present-but-invalid token is rejected outright rather than ignored, so a forged token cannot
silently downgrade to anonymous.

## Authorisation

Permissions are resolved at token issuance and carried in the token, so authorising a request costs
no lookup. The trade-off: a permission change reaches a user with their next access token, within
the access TTL. Revoke their sessions when a withdrawal must be immediate.

The wildcard permission `system:root` satisfies every authority check, which makes a break-glass
account workable without enumerating hundreds of permissions on it. One caveat worth repeating:
code that inspects `getAuthorities()` directly bypasses the SpEL handler and ignores the wildcard,
so the break-glass account gets refused by exactly the branch it exists for. Use
`WildcardPermissions.holdsAuthority(...)` for manual checks.

## Transport and browser

HSTS, a CSP tight enough for a JSON API, `frame-ancestors 'none'` against clickjacking, and a
referrer policy that keeps tokens in query strings from leaking cross-origin.

CORS accepts explicit origins only. A reflected wildcard combined with credentials lets any site
issue authenticated cross-origin requests from a logged-in user's browser.

CSRF protection is off, and that is correct here: authentication is a bearer token, not a cookie
session. The one cookie the library can set is the refresh token, and it is `SameSite=Strict`,
HttpOnly and scoped to the API path.

## What the library does not do

- **Authorisation modelling.** It resolves roles into permissions; deciding what a permission means
  is your application's job.
- **Delivery.** No mailer, no SMS gateway. It produces secrets and hands them to your
  `AuthMessenger`.
- **User lifecycle.** Creating, disabling and deleting users stays in your application. The library
  is told about status through `AuthUserDirectory`.
- **Federated identity.** No SAML, no social login. It authenticates against its own credentials;
  an external provider is a different integration.
