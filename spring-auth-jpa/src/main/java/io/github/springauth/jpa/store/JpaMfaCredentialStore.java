package io.github.springauth.jpa.store;

import java.util.Optional;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.MfaCredential;
import io.github.springauth.core.port.MfaCredentialStore;
import io.github.springauth.jpa.entity.AuthMfaCredentialEntity;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** JPA adapter of {@link MfaCredentialStore}. */
@Transactional(propagation = Propagation.MANDATORY)
public class JpaMfaCredentialStore implements MfaCredentialStore {

    private final EntityManager entityManager;

    public JpaMfaCredentialStore(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public Optional<MfaCredential> findByUserId(AuthUserId userId) {
        return findEntity(userId).map(AuthMfaCredentialEntity::toDomain);
    }

    @Override
    public Optional<MfaCredential> findByUserIdForUpdate(AuthUserId userId) {
        return queryEntity(userId).setLockMode(LockModeType.PESSIMISTIC_WRITE)
                .getResultStream().findFirst().map(AuthMfaCredentialEntity::toDomain);
    }

    @Override
    public MfaCredential save(MfaCredential credential) {
        Optional<AuthMfaCredentialEntity> existing = findEntity(credential.getUserId());
        if (existing.isPresent()) {
            existing.get().applyFrom(credential);
        } else {
            entityManager.persist(AuthMfaCredentialEntity.fromDomain(credential));
        }
        // MFA reset and confirmation are security boundaries.  Flush before the HTTP handler
        // acknowledges success so an database write failure can never leave a confirmed factor
        // behind after a successful reset response.
        entityManager.flush();
        return credential;
    }

    @Override
    public void deleteByUserId(AuthUserId userId) {
        entityManager.createQuery("delete from AuthMfaCredentialEntity m where m.userId = :userId")
                .setParameter("userId", userId.value())
                .executeUpdate();
    }

    private Optional<AuthMfaCredentialEntity> findEntity(AuthUserId userId) {
        return queryEntity(userId).getResultStream().findFirst();
    }

    private jakarta.persistence.TypedQuery<AuthMfaCredentialEntity> queryEntity(AuthUserId userId) {
        return entityManager.createQuery(
                        "select m from AuthMfaCredentialEntity m where m.userId = :userId",
                        AuthMfaCredentialEntity.class)
                .setParameter("userId", userId.value());
    }
}
