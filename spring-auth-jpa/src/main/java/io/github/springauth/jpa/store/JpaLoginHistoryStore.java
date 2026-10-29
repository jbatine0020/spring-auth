package io.github.springauth.jpa.store;

import java.time.Instant;
import java.util.List;

import jakarta.persistence.EntityManager;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.LoginAttempt;
import io.github.springauth.core.port.LoginHistoryStore;
import io.github.springauth.jpa.entity.AuthLoginAttemptEntity;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** JPA adapter of {@link LoginHistoryStore}. */
@Transactional(propagation = Propagation.MANDATORY)
public class JpaLoginHistoryStore implements LoginHistoryStore {

    private final EntityManager entityManager;

    public JpaLoginHistoryStore(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public void append(LoginAttempt attempt) {
        entityManager.persist(AuthLoginAttemptEntity.fromDomain(attempt));
    }

    @Override
    public List<LoginAttempt> findRecentByUserId(AuthUserId userId, int limit) {
        return entityManager.createQuery(
                        "select a from AuthLoginAttemptEntity a where a.userId = :userId "
                                + "order by a.occurredAt desc",
                        AuthLoginAttemptEntity.class)
                .setParameter("userId", userId.value())
                .setMaxResults(Math.max(1, limit))
                .getResultList()
                .stream()
                .map(AuthLoginAttemptEntity::toDomain)
                .toList();
    }

    @Override
    public long countFailuresSince(AuthUserId userId, Instant since) {
        return entityManager.createQuery(
                        "select count(a) from AuthLoginAttemptEntity a "
                                + "where a.userId = :userId and a.successful = false "
                                + "and a.occurredAt >= :since",
                        Long.class)
                .setParameter("userId", userId.value())
                .setParameter("since", since)
                .getSingleResult();
    }

    @Override
    public long countSuccessfulSince(Instant since) {
        return entityManager.createQuery("select count(a) from AuthLoginAttemptEntity a "
                        + "where a.successful = true and a.occurredAt >= :since", Long.class)
                .setParameter("since", since)
                .getSingleResult();
    }

    @Override
    public int deleteBefore(Instant before) {
        return entityManager.createQuery(
                        "delete from AuthLoginAttemptEntity a where a.occurredAt < :before")
                .setParameter("before", before)
                .executeUpdate();
    }
}
