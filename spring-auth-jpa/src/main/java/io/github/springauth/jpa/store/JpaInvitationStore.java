package io.github.springauth.jpa.store;

import java.time.Instant;
import java.util.Optional;

import jakarta.persistence.EntityManager;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.UserInvitation;
import io.github.springauth.core.port.InvitationStore;
import io.github.springauth.jpa.entity.AuthInvitationEntity;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** JPA adapter of {@link InvitationStore}. */
@Transactional(propagation = Propagation.MANDATORY)
public class JpaInvitationStore implements InvitationStore {

    private final EntityManager entityManager;

    public JpaInvitationStore(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public Optional<UserInvitation> findByTokenHash(String tokenHash) {
        return entityManager.createQuery(
                        "select i from AuthInvitationEntity i where i.tokenHash = :hash",
                        AuthInvitationEntity.class)
                .setParameter("hash", tokenHash)
                .getResultStream()
                .findFirst()
                .map(AuthInvitationEntity::toDomain);
    }

    @Override
    public UserInvitation save(UserInvitation invitation) {
        AuthInvitationEntity managed = entityManager.find(AuthInvitationEntity.class, invitation.getId());
        if (managed != null) {
            managed.applyFrom(invitation);
        } else {
            entityManager.persist(AuthInvitationEntity.fromDomain(invitation));
        }
        return invitation;
    }

    @Override
    public void deleteByUserId(AuthUserId userId) {
        entityManager.createQuery("delete from AuthInvitationEntity i where i.userId = :userId")
                .setParameter("userId", userId.value())
                .executeUpdate();
        entityManager.clear();
    }

    @Override
    public int deleteExpiredBefore(Instant before) {
        return entityManager.createQuery(
                        "delete from AuthInvitationEntity i where i.expiresAt < :before")
                .setParameter("before", before)
                .executeUpdate();
    }
}
