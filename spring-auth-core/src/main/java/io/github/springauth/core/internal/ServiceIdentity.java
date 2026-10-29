package io.github.springauth.core.internal;

import java.util.Objects;

/**
 * The calling service behind an internal request, once its token has been validated.
 *
 * @param serviceId identifier of the peer, as declared in {@code spring-auth.internal.peers}
 */
public record ServiceIdentity(String serviceId) {

    public ServiceIdentity {
        Objects.requireNonNull(serviceId, "serviceId is required");
        if (serviceId.isBlank()) {
            throw new IllegalArgumentException("serviceId is required");
        }
    }
}
