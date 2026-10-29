package io.github.springauth.jpa.entity;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import io.github.springauth.core.identity.IdentityUserMirror;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity
@Table(name = "auth_identity_mirrors", uniqueConstraints = @UniqueConstraint(
        name = "uk_auth_identity_provider_subject", columnNames = {"provider_id", "external_subject"}))
public class IdentityUserMirrorEntity {

    @Id
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "provider_id", nullable = false, length = 64)
    private String providerId;

    @Column(name = "external_subject", nullable = false, length = 256)
    private String externalSubject;

    @Column(name = "login", length = 320)
    private String login;

    @Column(name = "display_name", length = 256)
    private String displayName;

    @Column(name = "email", length = 320)
    private String email;

    @Column(name = "status", nullable = false, length = 32)
    private String status;

    @Column(name = "mfa_required", nullable = false)
    private boolean mfaRequired;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "auth_identity_mirror_roles", joinColumns = @JoinColumn(name = "mirror_id"))
    @Column(name = "role_code", nullable = false, length = 64)
    private Set<String> roleCodes = new HashSet<>();

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected IdentityUserMirrorEntity() {
    }

    public static IdentityUserMirrorEntity fromDomain(IdentityUserMirror mirror) {
        IdentityUserMirrorEntity entity = new IdentityUserMirrorEntity();
        entity.applyFrom(mirror);
        return entity;
    }

    public void applyFrom(IdentityUserMirror mirror) {
        id = mirror.id();
        providerId = mirror.providerId();
        externalSubject = mirror.externalSubject();
        login = mirror.login();
        displayName = mirror.displayName();
        email = mirror.email();
        status = mirror.status();
        mfaRequired = mirror.mfaRequired();
        roleCodes.clear();
        roleCodes.addAll(mirror.roleCodes());
        createdAt = mirror.createdAt();
        updatedAt = mirror.updatedAt();
    }

    public IdentityUserMirror toDomain() {
        return new IdentityUserMirror(id, providerId, externalSubject, login, displayName, email,
                status, mfaRequired, roleCodes, createdAt, updatedAt);
    }

    public UUID getId() { return id; }
}
