package io.github.springauth.jpa.store;

import java.time.Instant;
import java.util.List;

import jakarta.persistence.EntityManager;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.port.PasswordHistoryStore;
import io.github.springauth.jpa.entity.AuthPasswordHistoryEntity;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * JPA adapter of {@link PasswordHistoryStore}.
 *
 * <p>{@link #append} prunes past the retention window as it writes, so the table stays bounded
 * without a separate job. Old hashes are of no use to the no-reuse rule and of real use to anyone
 * who steals the table.
 */
@Transactional(propagation = Propagation.MANDATORY)
public class JpaPasswordHistoryStore implements PasswordHistoryStore {

    /** How many entries to keep, regardless of the configured comparison window. */
    private static final int RETAINED_ENTRIES = 20;

    private final EntityManager entityManager;

    public JpaPasswordHistoryStore(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public List<String> findRecentHashes(AuthUserId userId, int limit) {
        return entityManager.createQuery(
                        "select h.passwordHash from AuthPasswordHistoryEntity h "
                                + "where h.userId = :userId order by h.setAt desc",
                        String.class)
                .setParameter("userId", userId.value())
                .setMaxResults(Math.max(1, limit))
                .getResultList();
    }

    @Override
    public void append(AuthUserId userId, String passwordHash, Instant setAt) {
        entityManager.persist(new AuthPasswordHistoryEntity(userId.value(), passwordHash, setAt));
        prune(userId);
    }

    @Override
    public void deleteByUserId(AuthUserId userId) {
        entityManager.createQuery("delete from AuthPasswordHistoryEntity h where h.userId = :userId")
                .setParameter("userId", userId.value())
                .executeUpdate();
    }

    private void prune(AuthUserId userId) {
        List<Instant> retained = entityManager.createQuery(
                        "select h.setAt from AuthPasswordHistoryEntity h "
                                + "where h.userId = :userId order by h.setAt desc",
                        Instant.class)
                .setParameter("userId", userId.value())
                .setMaxResults(RETAINED_ENTRIES)
                .getResultList();
        if (retained.size() < RETAINED_ENTRIES) {
            return;
        }
        Instant oldestRetained = retained.get(retained.size() - 1);
        entityManager.createQuery(
                        "delete from AuthPasswordHistoryEntity h "
                                + "where h.userId = :userId and h.setAt < :cutoff")
                .setParameter("userId", userId.value())
                .setParameter("cutoff", oldestRetained)
                .executeUpdate();
    }
}
