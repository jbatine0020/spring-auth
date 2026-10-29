package io.github.springauth.core.service;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.Comparator;
import java.util.Locale;

import io.github.springauth.core.error.RoleException;
import io.github.springauth.core.model.Role;
import io.github.springauth.core.port.RoleStore;
import org.springframework.transaction.annotation.Transactional;

/**
 * Administration of roles and their permission sets.
 *
 * <p>Roles are archived rather than deleted so that existing assignments and audit records stay
 * readable; an archived role simply grants nothing. System roles refuse every modification, which
 * is what stops an operator from emptying the role their own access depends on.
 *
 * <p>Changes take effect on the next access token, within the access TTL. Revoke the sessions of
 * the affected users when a withdrawal has to be immediate.
 */
@Transactional
public class RoleService {

    private final RoleStore roleStore;
    private final Clock clock;

    public RoleService(RoleStore roleStore, Clock clock) {
        this.roleStore = roleStore;
        this.clock = clock;
    }

    /**
     * @throws RoleException {@code ROLE_ALREADY_EXISTS} when the code is taken
     */
    public Role create(String code, String name, String description, Set<String> permissions) {
        Role role = Role.create(code, name, description, permissions, clock.instant());
        if (roleStore.existsByCode(role.getCode())) {
            throw RoleException.alreadyExists(role.getCode());
        }
        return roleStore.save(role);
    }

    /** Creates a profile with a backend-generated immutable functional code. */
    public Role createGenerated(String name, String description, Set<String> permissions) {
        String code;
        do {
            code = roleStore.nextProfileCode();
        } while (roleStore.existsByCode(code));
        return create(code, name, description, permissions);
    }

    /**
     * Seeds a protected role, typically at boot. Returns the existing one when it is already
     * there, so the call is idempotent across restarts.
     */
    public Role seedSystemRole(String code, String name, String description, Set<String> permissions) {
        Role role = Role.createSystem(code, name, description, permissions, clock.instant());
        return roleStore.findByCode(role.getCode()).orElseGet(() -> roleStore.save(role));
    }

    public Role rename(String code, String name, String description) {
        Role role = require(code);
        role.rename(name, description, clock.instant());
        return roleStore.save(role);
    }

    /** Replaces the permission set wholesale. There is no partial update on purpose. */
    public Role replacePermissions(String code, Set<String> permissions) {
        Role role = require(code);
        role.replacePermissions(permissions, clock.instant());
        return roleStore.save(role);
    }

    public Role archive(String code) {
        Role role = require(code);
        role.archive(clock.instant());
        return roleStore.save(role);
    }

    public Role restore(String code) {
        Role role = require(code);
        role.restore(clock.instant());
        return roleStore.save(role);
    }

    @Transactional(readOnly = true)
    public Role get(String code) {
        return require(code);
    }

    @Transactional(readOnly = true)
    public List<Role> list() {
        return roleStore.findAll();
    }

    @Transactional(readOnly = true)
    public RolePage search(String search, String status, int page, int size, String sort, boolean ascending) {
        String query = search == null ? "" : search.trim().toLowerCase(Locale.ROOT);
        List<Role> filtered = roleStore.findAll().stream()
                .filter(role -> query.isBlank() || (role.getCode() + " " + role.getName() + " "
                        + (role.getDescription() == null ? "" : role.getDescription()))
                        .toLowerCase(Locale.ROOT).contains(query))
                .filter(role -> status == null || status.isBlank() || role.getStatus().name().equalsIgnoreCase(status))
                .sorted(roleComparator(sort, ascending))
                .toList();
        int from = Math.min(page * size, filtered.size());
        int to = Math.min(from + size, filtered.size());
        return new RolePage(page, size, filtered.size(), filtered.subList(from, to));
    }

    private Comparator<Role> roleComparator(String sort, boolean ascending) {
        Comparator<Role> comparator = switch (sort == null ? "code" : sort) {
            case "name" -> Comparator.comparing(Role::getName, String.CASE_INSENSITIVE_ORDER);
            case "status" -> Comparator.comparing(role -> role.getStatus().name());
            default -> Comparator.comparing(Role::getCode, String.CASE_INSENSITIVE_ORDER);
        };
        return ascending ? comparator : comparator.reversed();
    }

    public record RolePage(int page, int size, long countAll, List<Role> list) {
        public int pages() { return size == 0 ? 0 : (int) Math.ceil((double) countAll / size); }
    }

    private Role require(String code) {
        String normalised = code == null ? "" : code.trim().toUpperCase();
        return roleStore.findByCode(normalised).orElseThrow(() -> RoleException.notFound(normalised));
    }
}
