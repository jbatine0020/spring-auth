package io.github.springauth.core.identity;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/** Application identity mirror. Roles are owned locally and never replaced by provider data. */
public record IdentityUserMirror(
        UUID id,
        String providerId,
        String externalSubject,
        String login,
        String displayName,
        String email,
        String status,
        boolean mfaRequired,
        Set<String> roleCodes,
        Instant createdAt,
        Instant updatedAt) {

    public IdentityUserMirror {
        roleCodes = roleCodes == null ? Set.of() : Set.copyOf(roleCodes);
    }

    public IdentityUserMirror withProviderAttributes(String login, String displayName,
                                                      String email, Instant updatedAt) {
        return new IdentityUserMirror(id, providerId, externalSubject, login, displayName, email,
                status, mfaRequired, roleCodes, createdAt, updatedAt);
    }

    public IdentityUserMirror provision(String status, Set<String> roleCodes,
                                        boolean mfaRequired, Instant updatedAt) {
        return new IdentityUserMirror(id, providerId, externalSubject, login, displayName, email,
                status, mfaRequired, roleCodes, createdAt, updatedAt);
    }
}
