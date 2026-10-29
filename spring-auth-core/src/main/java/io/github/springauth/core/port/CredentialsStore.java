package io.github.springauth.core.port;

import java.util.Optional;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.Credentials;

/**
 * Persistence of password material.
 *
 * <p>Implemented out of the box by {@code spring-auth-jpa}. Implement it yourself only when your
 * passwords live somewhere the library cannot reach: an existing table with its own shape, or an
 * external directory.
 */
public interface CredentialsStore {

    Optional<Credentials> findByUserId(AuthUserId userId);

    Credentials save(Credentials credentials);

    void deleteByUserId(AuthUserId userId);
}
