package io.github.springauth.jpa.store;

import java.util.Optional;

import jakarta.persistence.EntityManager;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.Credentials;
import io.github.springauth.core.port.CredentialsStore;
import io.github.springauth.jpa.entity.AuthCredentialsEntity;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * JPA adapter of {@link CredentialsStore}.
 *
 * <p>Written against {@link EntityManager} rather than a Spring Data repository on purpose: a
 * library that declared its own repositories would have to enable repository scanning, which
 * switches off the auto-configured scan of the consuming application and silently breaks its own
 * repositories.
 */
@Transactional(propagation = Propagation.MANDATORY)
public class JpaCredentialsStore implements CredentialsStore {

    private final EntityManager entityManager;

    public JpaCredentialsStore(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public Optional<Credentials> findByUserId(AuthUserId userId) {
        return findEntity(userId).map(AuthCredentialsEntity::toDomain);
    }

    @Override
    public Credentials save(Credentials credentials) {
        // Updates an already-managed row in place when it exists, so a save inside the same
        // transaction as the load does not turn into a detached-entity merge.
        Optional<AuthCredentialsEntity> existing = findEntity(credentials.getUserId());
        if (existing.isPresent()) {
            existing.get().applyFrom(credentials);
        } else {
            entityManager.persist(AuthCredentialsEntity.fromDomain(credentials));
        }
        return credentials;
    }

    @Override
    public void deleteByUserId(AuthUserId userId) {
        entityManager.createQuery("delete from AuthCredentialsEntity c where c.userId = :userId")
                .setParameter("userId", userId.value())
                .executeUpdate();
    }

    private Optional<AuthCredentialsEntity> findEntity(AuthUserId userId) {
        return entityManager.createQuery(
                        "select c from AuthCredentialsEntity c where c.userId = :userId",
                        AuthCredentialsEntity.class)
                .setParameter("userId", userId.value())
                .getResultStream()
                .findFirst();
    }
}
