package io.github.springauth.jpa.store;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.RefreshToken;
import io.github.springauth.core.port.RefreshTokenStore;
import io.github.springauth.jpa.entity.AuthRefreshTokenEntity;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * JPA adapter of {@link RefreshTokenStore}.
 *
 * <p>Family and per-user revocation are bulk updates: a family can hold dozens of rows after a
 * long-lived session, and loading them one by one to flip a timestamp would be pure waste on a
 * path that runs while an attack is in progress.
 */
@Transactional(propagation = Propagation.MANDATORY)
public class JpaRefreshTokenStore implements RefreshTokenStore {

    private final EntityManager entityManager;

    public JpaRefreshTokenStore(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public Optional<RefreshToken> findByTokenHash(String tokenHash) {
        return findByHash(tokenHash, false);
    }

    @Override
    public Optional<RefreshToken> findByTokenHashForUpdate(String tokenHash) {
        return findByHash(tokenHash, true);
    }

    private Optional<RefreshToken> findByHash(String tokenHash, boolean lock) {
        // Revoked and expired rows are returned deliberately: replay detection needs them.
        var query = entityManager.createQuery(
                        "select t from AuthRefreshTokenEntity t where t.tokenHash = :hash",
                        AuthRefreshTokenEntity.class)
                .setParameter("hash", tokenHash);
        if (lock) query.setLockMode(LockModeType.PESSIMISTIC_WRITE);
        return query.getResultStream()
                .findFirst()
                .map(AuthRefreshTokenEntity::toDomain);
    }

    @Override
    public RefreshToken save(RefreshToken token) {
        AuthRefreshTokenEntity managed = entityManager.find(AuthRefreshTokenEntity.class, token.getId());
        if (managed != null) {
            managed.applyFrom(token);
        } else {
            entityManager.persist(AuthRefreshTokenEntity.fromDomain(token));
        }
        return token;
    }

    @Override
    public int revokeFamily(UUID familyId, Instant at) {
        int revoked = entityManager.createQuery(
                        "update AuthRefreshTokenEntity t set t.revokedAt = :at "
                                + "where t.familyId = :familyId and t.revokedAt is null")
                .setParameter("at", at)
                .setParameter("familyId", familyId)
                .executeUpdate();
        // A bulk update bypasses the persistence context, so anything already loaded would keep
        // showing a stale revokedAt within the same transaction.
        entityManager.clear();
        return revoked;
    }

    @Override
    public int revokeAllForUser(AuthUserId userId, Instant at) {
        int revoked = entityManager.createQuery(
                        "update AuthRefreshTokenEntity t set t.revokedAt = :at "
                                + "where t.userId = :userId and t.revokedAt is null")
                .setParameter("at", at)
                .setParameter("userId", userId.value())
                .executeUpdate();
        entityManager.clear();
        return revoked;
    }

    @Override
    public int deleteExpiredBefore(Instant before) {
        return entityManager.createQuery(
                        "delete from AuthRefreshTokenEntity t where t.expiresAt < :before")
                .setParameter("before", before)
                .executeUpdate();
    }
}
