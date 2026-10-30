package io.github.springauth.core.port;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import io.github.springauth.core.model.Role;

/** Persistence of roles and their permission sets. */
public interface RoleStore {

    Optional<Role> findByCode(String code);

    /**
     * Bulk lookup used on every login to expand a user's role codes into permissions.
     * Implementations should resolve it in one query.
     */
    List<Role> findByCodes(Collection<String> codes);

    List<Role> findAll();

    /** Filter, count and paginate in the persistence adapter. */
    Page search(String search, String status, int page, int size, String sort, boolean ascending);

    record Page(long total, List<Role> list) {}


    boolean existsByCode(String code);

    /** Returns the next unique functional code for a user-created profile. */
    String nextProfileCode();

    Role save(Role role);
}
