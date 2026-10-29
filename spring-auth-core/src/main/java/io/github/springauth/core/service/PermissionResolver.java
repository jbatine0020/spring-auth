package io.github.springauth.core.service;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.Role;
import io.github.springauth.core.port.RoleStore;

/**
 * Expands the role codes a user holds into the flat permission list written to their access token.
 *
 * <p>Resolution happens at token issuance, not at request time: the token carries the answer, so
 * authorising a request costs no lookup. The trade-off is that a permission change only reaches a
 * user when their next access token is minted, within the access TTL, five minutes by default.
 * Revoke their sessions if a change has to take effect immediately.
 *
 * <p>Archived roles contribute nothing, which is what makes archiving a role an effective way to
 * withdraw its permissions without touching assignments.
 */
public class PermissionResolver {

    private final RoleStore roleStore;

    public PermissionResolver(RoleStore roleStore) {
        this.roleStore = roleStore;
    }

    /** Union of the permissions of every active role the user holds. */
    public Set<String> resolve(AuthUser user) {
        if (user.roleCodes().isEmpty()) {
            return Set.of();
        }
        List<Role> roles = roleStore.findByCodes(user.roleCodes());
        LinkedHashSet<String> permissions = new LinkedHashSet<>();
        for (Role role : roles) {
            if (role.isActive()) {
                permissions.addAll(role.getPermissions());
            }
        }
        return Set.copyOf(permissions);
    }
}
