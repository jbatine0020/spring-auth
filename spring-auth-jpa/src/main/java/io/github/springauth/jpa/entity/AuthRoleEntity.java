package io.github.springauth.jpa.entity;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import io.github.springauth.core.model.Role;
import io.github.springauth.core.model.RoleStatus;

/**
 * Row of {@code auth_roles}, with its permissions in {@code auth_role_permissions}.
 *
 * <p>Permissions are eagerly fetched: a role is only ever loaded to expand it into a token, so a
 * lazy collection would guarantee a second query every time and an occasional
 * {@code LazyInitializationException} outside a session.
 */
@Entity
@Table(name = "auth_roles")
public class AuthRoleEntity {

    @Id
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "code", nullable = false, unique = true, length = 64)
    private String code;

    @Column(name = "name", nullable = false, length = 128)
    private String name;

    @Column(name = "description", length = 512)
    private String description;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "auth_role_permissions",
            joinColumns = @JoinColumn(name = "role_id"))
    @Column(name = "permission", nullable = false, length = 128)
    private Set<String> permissions = new HashSet<>();

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private RoleStatus status;

    @Column(name = "system_role", nullable = false)
    private boolean systemRole;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected AuthRoleEntity() {
        // required by JPA
    }

    public static AuthRoleEntity fromDomain(Role role) {
        AuthRoleEntity entity = new AuthRoleEntity();
        entity.applyFrom(role);
        return entity;
    }

    public void applyFrom(Role role) {
        this.id = role.getId();
        this.code = role.getCode();
        this.name = role.getName();
        this.description = role.getDescription();
        // Mutated in place rather than replaced: Hibernate tracks this collection instance, and
        // swapping it for a new Set makes it delete and reinsert every row on each save.
        this.permissions.clear();
        this.permissions.addAll(role.getPermissions());
        this.status = role.getStatus();
        this.systemRole = role.isSystem();
        this.createdAt = role.getCreatedAt();
        this.updatedAt = role.getUpdatedAt();
    }

    public Role toDomain() {
        return Role.restore(id, code, name, description, Set.copyOf(permissions), status,
                systemRole, createdAt, updatedAt);
    }

    public UUID getId() {
        return id;
    }

    public String getCode() {
        return code;
    }
}
