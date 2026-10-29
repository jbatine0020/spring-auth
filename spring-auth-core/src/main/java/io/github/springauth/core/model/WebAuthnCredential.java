package io.github.springauth.core.model;

import java.time.Instant;
import java.util.Arrays;

/** Persisted WebAuthn credential metadata; the authenticator key remains opaque to the domain. */
public record WebAuthnCredential(
        String credentialId,
        AuthUserId userId,
        byte[] publicKey,
        long signatureCounter,
        String displayName,
        Instant createdAt,
        Instant lastUsedAt) {

    public WebAuthnCredential {
        if (credentialId == null || credentialId.isBlank() || userId == null
                || publicKey == null || publicKey.length == 0) {
            throw new IllegalArgumentException("invalid WebAuthn credential");
        }
        publicKey = Arrays.copyOf(publicKey, publicKey.length);
    }

    @Override
    public byte[] publicKey() {
        return Arrays.copyOf(publicKey, publicKey.length);
    }
}
