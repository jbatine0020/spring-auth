package io.github.springauth.core.identity;

import java.util.Map;

/** Normalized identity returned by a provider after a successful authentication. */
public record IdentityAuthenticationResult(
        String externalSubject,
        String login,
        String displayName,
        String email,
        Map<String, String> attributes) {

    public IdentityAuthenticationResult {
        if (externalSubject == null || externalSubject.isBlank()) {
            throw new IllegalArgumentException("externalSubject must not be blank");
        }
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }
}
