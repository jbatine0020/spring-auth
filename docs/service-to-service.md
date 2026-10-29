# Service-to-service authentication

Short-lived HS256 tokens between your own services, plus HMAC signatures on request bodies. Off by
default.

## When to use it

A call between two services you operate, where no user is involved: a scheduled job in one service
calling an endpoint in another, a webhook, an internal lookup. Forwarding a user's access token
would be the wrong answer. It grants the caller everything that user can do, and it fails the
moment the token expires mid-job.

## Why symmetric signing here

Access tokens are RS256 with a published JWKS, because any number of parties must verify them
without being able to mint them. Internal tokens are the opposite situation: two ends of a trusted
boundary sharing a secret, calls that live two minutes, and no third party in the picture. HS256
avoids a key distribution problem for no loss.

## Configuration

Both sides declare who they are and the secret they share.

```yaml
# In service "orders"
spring-auth:
  internal:
    enabled: true
    service-id: orders
    peers:
      billing: ${SHARED_SECRET_ORDERS_BILLING}
```

```yaml
# In service "billing"
spring-auth:
  internal:
    enabled: true
    service-id: billing
    peers:
      orders: ${SHARED_SECRET_ORDERS_BILLING}
```

The secret must be at least 32 characters, which HS256 requires for a 256-bit key. The library
refuses to start otherwise rather than silently signing with a weak key.

Use a distinct secret per pair of services. One shared secret across a fleet means any compromised
service can impersonate any other.

## Calling a peer

```java
@Component
class BillingClient {

    private final InternalTokenService tokens;
    private final RestClient restClient;

    void notifyPaid(String orderId) {
        restClient.post()
                .uri("https://billing.internal/api/orders/{id}:paid", orderId)
                .header("X-Internal-Token", tokens.issueFor("billing"))
                .retrieve()
                .toBodilessEntity();
    }
}
```

`issueFor` pins the audience to the callee. That matters: without it, a token captured on a call to
one service could be replayed against another service sharing the same secret.

Mint a token per call. They are cheap, they last two minutes, and reusing one widens the window in
which a captured token is useful.

## Receiving a call

Nothing to write. `InternalServiceAuthFilter` validates the header and populates the security
context with an `InternalAuthentication` carrying two authorities:

- `ROLE_INTERNAL_SERVICE` for any authenticated peer
- `internal:<serviceId>` for one specific peer

Gate the endpoint accordingly:

```java
@PostMapping("/api/orders/{id}:paid")
@PreAuthorize("hasAuthority('internal:billing')")
public void markPaid(@PathVariable String id) { ... }
```

Prefer the specific authority. Sharing a trust boundary between services is not the same as letting
every service call every endpoint.

An internal authentication carries no user permission. The call acts as a service, not on behalf of
a person, and conflating the two is how a machine account ends up with more reach than any human.

A header that is present but invalid is rejected outright rather than ignored. Falling through to
anonymous would turn a forged token into a silent downgrade, surfacing much later as a confusing
`403`.

## What makes a captured token useless

Three checks, and all three are needed.

**A short expiry.** Two minutes by default.

**Audience pinning.** The token names the callee, and the callee refuses one addressed elsewhere.

**One-shot `jti`.** Each token identifier is registered on first use and refused afterwards.
Signature and expiry alone would leave a two-minute replay window open to anyone able to observe a
call.

The replay guard is in memory by default, which is per instance. Behind more than one replica it
must be shared, and the starter swaps it for the Redis-backed one as soon as Spring Data Redis is
present. Without that, a token replayed against a different instance goes through.

## Signing a request body

The token says who is calling. The signature says the payload was not altered on the way. Useful
for webhooks and for any call where the body carries something worth tampering with.

Sending:

```java
byte[] body = objectMapper.writeValueAsBytes(payload);
String signature = BodySignature.sign(sharedSecret, body);

restClient.post()
        .uri("https://billing.internal/api/hooks/order")
        .header("X-Internal-Token", tokens.issueFor("billing"))
        .header("X-Signature", "sha256=" + signature)
        .body(body)
        .retrieve()
        .toBodilessEntity();
```

Receiving is automatic. `WebhookSignatureFilter` runs after the peer is identified, so it verifies
with the secret of the peer that just proved its identity, and it buffers the body so the
controller can still read it.

Comparison is constant-time. A naive string comparison on hex leaks, through timing, how many
leading characters matched, which is enough to reconstruct a signature byte by byte.

## Rotating a shared secret

There is no dual-secret window, so rotate in a maintenance window or accept a brief window of
refused calls:

1. Generate the new secret.
2. Deploy the callee with it. Calls from the caller now fail.
3. Deploy the caller with it. Calls resume.

Keep the window short. Internal tokens live two minutes, so there is no long tail of in-flight
credentials to wait out.

If your calls must never fail, put the two services behind a retry with backoff for the duration of
the rotation. The library does not retry on your behalf.

## Troubleshooting

**`401 INTERNAL_AUTH_FAILED` on every call.** The server log carries the reason, which is
deliberately not in the response. Look for the peer name: a missing secret entry, a mismatched
`service-id`, or an audience pointing at the wrong service.

**Calls work on one instance and fail on another.** The replay guard is not shared. Add Redis.

**Signature always refused.** The body is being serialised twice, once for signing and once for
sending, and the two byte arrays differ. Sign the exact bytes you send.
