package io.github.springauth.core.model;

/**
 * Lifecycle of a role.
 *
 * <p>Roles are archived rather than deleted: existing assignments keep referring to them, and the
 * audit trail stays readable. An archived role contributes no permission.
 */
public enum RoleStatus {

    ACTIVE,

    ARCHIVED
}
