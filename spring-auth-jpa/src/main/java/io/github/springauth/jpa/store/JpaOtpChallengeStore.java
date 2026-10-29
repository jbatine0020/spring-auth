package io.github.springauth.jpa.store;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.OtpChallenge;
import io.github.springauth.core.model.OtpChannel;
import io.github.springauth.core.port.OtpChallengeStore;
import io.github.springauth.jpa.entity.AuthOtpChallengeEntity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import java.util.Optional;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** PostgreSQL adapter using a pessimistic lock so concurrent validation cannot consume a code twice. */
@Transactional(propagation = Propagation.MANDATORY)
public class JpaOtpChallengeStore implements OtpChallengeStore {
    private final EntityManager entityManager;
    public JpaOtpChallengeStore(EntityManager entityManager) { this.entityManager = entityManager; }
    @Override public Optional<OtpChallenge> findForUpdate(AuthUserId userId, OtpChannel channel) {
        return entityManager.createQuery("select c from AuthOtpChallengeEntity c where c.userId=:userId and c.channel=:channel", AuthOtpChallengeEntity.class)
                .setParameter("userId", userId.value()).setParameter("channel", channel)
                .setLockMode(LockModeType.PESSIMISTIC_WRITE).setMaxResults(1).getResultStream().findFirst()
                .map(AuthOtpChallengeEntity::toDomain);
    }
    @Override public OtpChallenge save(OtpChallenge challenge) {
        var entity = entityManager.find(AuthOtpChallengeEntity.class, challenge.id());
        if (entity == null) entityManager.persist(AuthOtpChallengeEntity.from(challenge)); else entity.apply(challenge);
        return challenge;
    }
}
