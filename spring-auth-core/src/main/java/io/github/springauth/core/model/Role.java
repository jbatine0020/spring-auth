package io.github.springauth.core.model;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * A named bundle of permissions.
 *
 * <p>Users hold role codes (supplied by the host application through
 * {@link io.github.springauth.core.spi.AuthUserDirectory}); the library expands those codes
 * into the permission list it writes into the access token. Keeping the mapping here means a role
 * change takes effect on the next token, without touching the user records.
 *
 * <p>System roles are seeded by the application and cannot be renamed, re-scoped or archived
 * through the administration API, that is what keeps an operator from accidentally emptying the
 * role every administrator depends on.
 */
public final class Role {

    /**
     * Wildcard permission: a role carrying it satisfies every {@code hasAuthority(...)} check.
     * Grant it to a single break-glass role and to nothing else.
     */
    public static final String WILDCARD_PERMISSION = "system:root";

    private final UUID id;
    private final String code;
    private String name;
    private String description;
    private Set<String> permissions;
    private RoleStatus status;
    private final boolean system;
    private final Instant createdAt;
    private Instant updatedAt;

    private Role(UUID id, String code, String name, String description, Set<String> permissions,
                 RoleStatus status, boolean system, Instant createdAt, Instant updatedAt) {
        this.id = Objects.requireNonNull(id, "id is required");
        this.code = normaliseCode(code);
        this.name = requireNotBlank(name, "name");
        this.description = description;
        this.permissions = normalisePermissions(permissions);
        this.status = Objects.requireNonNull(status, "status is required");
        this.system = system;
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt is required");
        this.updatedAt = Objects.requireNonNull(updatedAt, "updatedAt is required");
    }

    public static Role create(String code, String name, String description,
                              Set<String> permissions, Instant now) {
        return new Role(UUID.randomUUID(), code, name, description, permissions,
                RoleStatus.ACTIVE, false, now, now);
    }

    /** Seeds a protected role that the administration API refuses to modify. */
    public static Role createSystem(String code, String name, String description,
                                    Set<String> permissions, Instant now) {
        return new Role(UUID.randomUUID(), code, name, description, permissions,
                RoleStatus.ACTIVE, true, now, now);
    }

    /** Rebuilds an instance from storage. Used by persistence adapters only. */
    public static Role restore(UUID id, String code, String name, String description,
                               Set<String> permissions, RoleStatus status, boolean system,
                               Instant createdAt, Instant updatedAt) {
        return new Role(id, code, name, description, permissions, status, system, createdAt, updatedAt);
    }

    public void rename(String newName, String newDescription, Instant now) {
        requireMutable();
        this.name = requireNotBlank(newName, "name");
        this.description = newDescription;
        this.updatedAt = now;
    }

    /** Replaces the permission set wholesale. The administration API has no partial update. */
    public void replacePermissions(Set<String> newPermissions, Instant now) {
        requireMutable();
        this.permissions = normalisePermissions(newPermissions);
        this.updatedAt = now;
    }

    public void archive(Instant now) {
        requireMutable();
        this.status = RoleStatus.ARCHIVED;
        this.updatedAt = now;
    }

    public void restore(Instant now) {
        requireMutable();
        this.status = RoleStatus.ACTIVE;
        this.updatedAt = now;
    }

    public boolean isActive() {
        return status == RoleStatus.ACTIVE;
    }

    public boolean grantsWildcard() {
        return permissions.contains(WILDCARD_PERMISSION);
    }

    private void requireMutable() {
        if (system) {
            throw new IllegalStateException("Role " + code + " is a system role and cannot be modified");
        }
    }

    private static String normaliseCode(String code) {
        String value = requireNotBlank(code, "code").trim().toUpperCase();
        if (!value.matches("[A-Z0-9_.-]{2,64}")) {
            throw new IllegalArgumentException(
                    "Role code must be 2 to 64 characters of A-Z, 0-9, underscore, dot or dash: " + value);
        }
        return value;
    }

    private static Set<String> normalisePermissions(Set<String> permissions) {
        if (permissions == null) {
            return Set.of();
        }
        LinkedHashSet<String> cleaned = new LinkedHashSet<>();
        for (String permission : permissions) {
            if (permission != null && !permission.isBlank()) {
                cleaned.add(permission.trim());
            }
        }
        return Set.copyOf(cleaned);
    }

    private static String requireNotBlank(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }

    public UUID getId() {
        return id;
    }

    public String getCode() {
        return code;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    /** Defensive copy. Mutate through {@link #replacePermissions} only. */
    public Set<String> getPermissions() {
        return Set.copyOf(permissions);
    }

    public RoleStatus getStatus() {
        return status;
    }

    public boolean isSystem() {
        return system;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
