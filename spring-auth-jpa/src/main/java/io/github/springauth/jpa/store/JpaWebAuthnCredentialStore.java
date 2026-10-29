package io.github.springauth.jpa.store;

import java.util.List;
import java.util.Optional;

import jakarta.persistence.EntityManager;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.WebAuthnCredential;
import io.github.springauth.core.port.WebAuthnCredentialStore;
import io.github.springauth.jpa.entity.AuthWebAuthnCredentialEntity;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Transactional(propagation = Propagation.MANDATORY)
public class JpaWebAuthnCredentialStore implements WebAuthnCredentialStore {
    private final EntityManager entityManager;
    public JpaWebAuthnCredentialStore(EntityManager entityManager) { this.entityManager = entityManager; }
    public List<WebAuthnCredential> findByUserId(AuthUserId id) { return entityManager.createQuery(
            "select c from AuthWebAuthnCredentialEntity c where c.userId = :id", AuthWebAuthnCredentialEntity.class)
            .setParameter("id", id.value()).getResultStream().map(AuthWebAuthnCredentialEntity::toDomain).toList(); }
    public Optional<WebAuthnCredential> findByCredentialId(String id) { return Optional.ofNullable(entityManager.find(AuthWebAuthnCredentialEntity.class, id)).map(AuthWebAuthnCredentialEntity::toDomain); }
    public WebAuthnCredential save(WebAuthnCredential c) { AuthWebAuthnCredentialEntity e = entityManager.find(AuthWebAuthnCredentialEntity.class, c.credentialId()); if (e == null) entityManager.persist(AuthWebAuthnCredentialEntity.fromDomain(c)); return c; }
    public boolean acceptSignatureCounter(String id, long counter) {
        return entityManager.createQuery("update AuthWebAuthnCredentialEntity c set c.signatureCounter = :counter, c.lastUsedAt = CURRENT_TIMESTAMP where c.credentialId = :id and c.signatureCounter < :counter")
                .setParameter("counter", counter).setParameter("id", id).executeUpdate() == 1;
    }
    public void deleteByCredentialId(String id) { entityManager.createQuery("delete from AuthWebAuthnCredentialEntity c where c.credentialId = :id").setParameter("id", id).executeUpdate(); }
}
