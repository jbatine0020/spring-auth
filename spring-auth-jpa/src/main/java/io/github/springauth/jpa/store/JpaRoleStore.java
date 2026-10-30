package io.github.springauth.jpa.store;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import jakarta.persistence.EntityManager;
import io.github.springauth.core.model.Role;
import io.github.springauth.core.port.RoleStore;
import io.github.springauth.jpa.entity.AuthRoleEntity;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** JPA adapter of {@link RoleStore}. */
@Transactional(propagation = Propagation.MANDATORY)
public class JpaRoleStore implements RoleStore {

    private final EntityManager entityManager;

    public JpaRoleStore(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public Optional<Role> findByCode(String code) {
        return findEntity(code).map(AuthRoleEntity::toDomain);
    }

    @Override
    public List<Role> findByCodes(Collection<String> codes) {
        if (codes == null || codes.isEmpty()) {
            return List.of();
        }
        // One query for the whole set: this runs on every token issuance.
        List<String> normalised = codes.stream()
                .filter(code -> code != null && !code.isBlank())
                .map(code -> code.trim().toUpperCase())
                .toList();
        if (normalised.isEmpty()) {
            return List.of();
        }
        return entityManager.createQuery(
                        "select distinct r from AuthRoleEntity r "
                                + "left join fetch r.permissions where r.code in :codes",
                        AuthRoleEntity.class)
                .setParameter("codes", normalised)
                .getResultList()
                .stream()
                .map(AuthRoleEntity::toDomain)
                .toList();
    }

    @Override
    public List<Role> findAll() {
        return entityManager.createQuery(
                        "select distinct r from AuthRoleEntity r "
                                + "left join fetch r.permissions order by r.code",
                        AuthRoleEntity.class)
                .getResultList()
                .stream()
                .map(AuthRoleEntity::toDomain)
                .toList();
    }

    @Override
    public RoleStore.Page search(String search, String status, int page, int size, String sort, boolean ascending) {
        String term = search == null ? "" : search.trim().toLowerCase(java.util.Locale.ROOT);
        // Escape LIKE metacharacters: user searches are literal strings.
        String pattern = "%" + term.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%";
        var roleStatus = status == null || status.isBlank() ? null
                : io.github.springauth.core.model.RoleStatus.valueOf(status.toUpperCase(java.util.Locale.ROOT));
        String where = " where lower(concat(r.code, ' ', r.name, ' ', coalesce(r.description, ''))) like :term escape '!'";
        if (roleStatus != null) where += " and r.status = :status";
        String column = switch (sort == null ? "code" : sort) { case "name" -> "lower(r.name)"; case "status" -> "r.status"; default -> "r.code"; };
        String order = " order by " + column + (ascending ? " asc" : " desc") + ", r.code asc";
        var count = entityManager.createQuery("select count(r) from AuthRoleEntity r" + where, Long.class).setParameter("term", pattern);
        var codes = entityManager.createQuery("select r.code from AuthRoleEntity r" + where + order, String.class).setParameter("term", pattern);
        if (roleStatus != null) { count.setParameter("status", roleStatus); codes.setParameter("status", roleStatus); }
        long total = count.getSingleResult();
        var pageCodes = codes.setFirstResult(Math.multiplyExact(page, size)).setMaxResults(size).getResultList();
        // Fetch collections only for this page; paginating a collection fetch join would page in memory.
        var roles = findByCodes(pageCodes).stream().collect(java.util.stream.Collectors.toMap(Role::getCode, role -> role));
        return new RoleStore.Page(total, pageCodes.stream().map(roles::get).toList());
    }

    @Override
    public boolean existsByCode(String code) {
        return entityManager.createQuery(
                        "select count(r) from AuthRoleEntity r where r.code = :code", Long.class)
                .setParameter("code", code)
                .getSingleResult() > 0;
    }

    @Override
    public String nextProfileCode() {
        Number value = (Number) entityManager
                .createNativeQuery("SELECT nextval('auth_profile_code_seq')")
                .getSingleResult();
        return String.format(java.util.Locale.ROOT, "PROF-%04d", value.longValue());
    }

    @Override
    public Role save(Role role) {
        Optional<AuthRoleEntity> existing = findEntity(role.getCode());
        if (existing.isPresent()) {
            existing.get().applyFrom(role);
        } else {
            entityManager.persist(AuthRoleEntity.fromDomain(role));
        }
        return role;
    }

    private Optional<AuthRoleEntity> findEntity(String code) {
        return entityManager.createQuery(
                        "select r from AuthRoleEntity r left join fetch r.permissions where r.code = :code",
                        AuthRoleEntity.class)
                .setParameter("code", code)
                .getResultStream()
                .findFirst();
    }
}
