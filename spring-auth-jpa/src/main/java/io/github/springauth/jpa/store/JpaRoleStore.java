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
