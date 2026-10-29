package io.github.springauth.jpa.store;

import java.util.Optional;

import io.github.springauth.core.identity.IdentityMirrorStore;
import io.github.springauth.core.identity.IdentityUserMirror;
import io.github.springauth.jpa.entity.IdentityUserMirrorEntity;
import jakarta.persistence.EntityManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Transactional(propagation = Propagation.MANDATORY)
public class JpaIdentityMirrorStore implements IdentityMirrorStore {

    private final EntityManager entityManager;

    public JpaIdentityMirrorStore(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public Optional<IdentityUserMirror> find(String providerId, String externalSubject) {
        return entityManager.createQuery(
                        "select m from IdentityUserMirrorEntity m where m.providerId = :providerId "
                                + "and m.externalSubject = :externalSubject",
                        IdentityUserMirrorEntity.class)
                .setParameter("providerId", providerId)
                .setParameter("externalSubject", externalSubject)
                .getResultStream()
                .findFirst()
                .map(IdentityUserMirrorEntity::toDomain);
    }

    @Override
    public Optional<IdentityUserMirror> findByLogin(String login) {
        return entityManager.createQuery("select m from IdentityUserMirrorEntity m where lower(m.login) = lower(:login)", IdentityUserMirrorEntity.class)
                .setParameter("login", login).setMaxResults(1).getResultStream()
                .findFirst().map(IdentityUserMirrorEntity::toDomain);
    }

    @Override
    public Optional<IdentityUserMirror> findById(java.util.UUID id) {
        return Optional.ofNullable(entityManager.find(IdentityUserMirrorEntity.class, id))
                .map(IdentityUserMirrorEntity::toDomain);
    }

    @Override
    public IdentityUserMirror save(IdentityUserMirror mirror) {
        Optional<IdentityUserMirrorEntity> existing = entityManager.createQuery(
                        "select m from IdentityUserMirrorEntity m where m.providerId = :providerId "
                                + "and m.externalSubject = :externalSubject",
                        IdentityUserMirrorEntity.class)
                .setParameter("providerId", mirror.providerId())
                .setParameter("externalSubject", mirror.externalSubject())
                .getResultStream()
                .findFirst();
        if (existing.isPresent()) {
            existing.get().applyFrom(mirror);
        } else {
            entityManager.persist(IdentityUserMirrorEntity.fromDomain(mirror));
        }
        return mirror;
    }
}
