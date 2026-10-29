package io.github.springauth.core.identity;

import java.time.Clock;
import java.time.Instant;
import java.util.Set;
import java.util.Optional;
import java.util.UUID;

/** Creates or updates a mirror without ever importing provider roles. */
public final class IdentityMirrorService {

    private final IdentityMirrorStore store;
    private final Clock clock;

    public IdentityMirrorService(IdentityMirrorStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    public IdentityUserMirror synchronize(IdentityProvider provider,
                                           IdentityAuthenticationResult identity) {
        Instant now = Instant.now(clock);
        return store.find(provider.providerId(), identity.externalSubject())
                .map(existing -> store.save(existing.withProviderAttributes(identity.login(),
                        identity.displayName(), identity.email(), now)))
                .orElseGet(() -> store.save(new IdentityUserMirror(
                        UUID.randomUUID(), provider.providerId(), identity.externalSubject(),
                        identity.login(), identity.displayName(), identity.email(), "ACTIVE", false,
                        Set.of(), now, now)));
    }

    /** Updates an identity already provisioned locally; it never imports a new account at login. */
    public Optional<IdentityUserMirror> synchronizeExisting(IdentityProvider provider,
                                                              IdentityAuthenticationResult identity) {
        Instant now = Instant.now(clock);
        return store.find(provider.providerId(), identity.externalSubject())
                .map(existing -> store.save(existing.withProviderAttributes(identity.login(),
                        identity.displayName(), identity.email(), now)));
    }
}
