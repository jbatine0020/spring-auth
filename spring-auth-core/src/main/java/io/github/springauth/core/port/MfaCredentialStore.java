package io.github.springauth.core.port;

import java.util.Optional;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.MfaCredential;

/** Persistence of enrolled TOTP factors. */
public interface MfaCredentialStore {

    Optional<MfaCredential> findByUserId(AuthUserId userId);

    /** Locks an existing factor until transaction completion before changing its replay counter. */
    Optional<MfaCredential> findByUserIdForUpdate(AuthUserId userId);

    MfaCredential save(MfaCredential credential);

    void deleteByUserId(AuthUserId userId);
}
