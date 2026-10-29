package io.github.springauth.jpa.store;

import java.time.Instant;
import java.util.Optional;

import jakarta.persistence.EntityManager;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.PasswordResetRequest;
import io.github.springauth.core.port.PasswordResetStore;
import io.github.springauth.jpa.entity.AuthPasswordResetEntity;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** JPA adapter of {@link PasswordResetStore}. */
@Transactional(propagation = Propagation.MANDATORY)
public class JpaPasswordResetStore implements PasswordResetStore {

    private final EntityManager entityManager;

    public JpaPasswordResetStore(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public Optional<PasswordResetRequest> findByTokenHash(String tokenHash) {
        return entityManager.createQuery(
                        "select r from AuthPasswordResetEntity r where r.tokenHash = :hash",
                        AuthPasswordResetEntity.class)
                .setParameter("hash", tokenHash)
                .getResultStream()
                .findFirst()
                .map(AuthPasswordResetEntity::toDomain);
    }

    @Override
    public PasswordResetRequest save(PasswordResetRequest request) {
        AuthPasswordResetEntity managed =
                entityManager.find(AuthPasswordResetEntity.class, request.getId());
        if (managed != null) {
            managed.applyFrom(request);
        } else {
            entityManager.persist(AuthPasswordResetEntity.fromDomain(request));
        }
        return request;
    }

    @Override
    public void deleteByUserId(AuthUserId userId) {
        entityManager.createQuery("delete from AuthPasswordResetEntity r where r.userId = :userId")
                .setParameter("userId", userId.value())
                .executeUpdate();
        entityManager.clear();
    }

    @Override
    public int deleteExpiredBefore(Instant before) {
        return entityManager.createQuery(
                        "delete from AuthPasswordResetEntity r where r.expiresAt < :before")
                .setParameter("before", before)
                .executeUpdate();
    }
}
