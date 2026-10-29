package io.github.springauth.core.port;

import java.util.List;
import java.util.Optional;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.WebAuthnCredential;

/** Persistence boundary for future WebAuthn registration and assertion flows. */
public interface WebAuthnCredentialStore {
    List<WebAuthnCredential> findByUserId(AuthUserId userId);
    Optional<WebAuthnCredential> findByCredentialId(String credentialId);
    WebAuthnCredential save(WebAuthnCredential credential);
    boolean acceptSignatureCounter(String credentialId, long newCounter);
    void deleteByCredentialId(String credentialId);
}
