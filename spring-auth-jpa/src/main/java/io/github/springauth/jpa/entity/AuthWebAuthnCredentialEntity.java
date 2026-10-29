package io.github.springauth.jpa.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.WebAuthnCredential;

/** PostgreSQL persistence row for a WebAuthn public credential. */
@Entity
@Table(name = "auth_webauthn_credentials")
public class AuthWebAuthnCredentialEntity {

    @Id
    @Column(name = "credential_id", length = 512, nullable = false)
    private String credentialId;

    @Column(name = "user_id", length = 64, nullable = false)
    private String userId;

    @Column(name = "public_key", nullable = false)
    private byte[] publicKey;

    @Column(name = "signature_counter", nullable = false)
    private long signatureCounter;

    @Column(name = "display_name", length = 160)
    private String displayName;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    protected AuthWebAuthnCredentialEntity() {
    }

    public static AuthWebAuthnCredentialEntity fromDomain(WebAuthnCredential c) {
        AuthWebAuthnCredentialEntity e = new AuthWebAuthnCredentialEntity();
        e.credentialId = c.credentialId(); e.userId = c.userId().value(); e.publicKey = c.publicKey();
        e.signatureCounter = c.signatureCounter(); e.displayName = c.displayName();
        e.createdAt = c.createdAt(); e.lastUsedAt = c.lastUsedAt(); return e;
    }

    public WebAuthnCredential toDomain() {
        return new WebAuthnCredential(credentialId, AuthUserId.of(userId), publicKey,
                signatureCounter, displayName, createdAt, lastUsedAt);
    }
}
