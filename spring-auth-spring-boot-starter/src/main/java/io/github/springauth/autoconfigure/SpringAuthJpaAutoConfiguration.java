package io.github.springauth.autoconfigure;

import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import io.github.springauth.core.port.CredentialsStore;
import io.github.springauth.core.port.InvitationStore;
import io.github.springauth.core.port.LoginHistoryStore;
import io.github.springauth.core.port.MfaCredentialStore;
import io.github.springauth.core.port.OtpChallengeStore;
import io.github.springauth.core.port.PasswordHistoryStore;
import io.github.springauth.core.port.PasswordResetStore;
import io.github.springauth.core.port.RefreshTokenStore;
import io.github.springauth.core.port.RoleStore;
import io.github.springauth.jpa.store.JpaCredentialsStore;
import io.github.springauth.jpa.store.JpaInvitationStore;
import io.github.springauth.jpa.store.JpaLoginHistoryStore;
import io.github.springauth.jpa.store.JpaMfaCredentialStore;
import io.github.springauth.jpa.store.JpaOtpChallengeStore;
import io.github.springauth.jpa.store.JpaPasswordHistoryStore;
import io.github.springauth.jpa.store.JpaPasswordResetStore;
import io.github.springauth.jpa.store.JpaRefreshTokenStore;
import io.github.springauth.jpa.store.JpaRoleStore;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

/**
 * Wires the JPA persistence adapters.
 *
 * <p>Active as soon as JPA is on the classpath. Turn it off with
 * {@code spring-auth.jpa.enabled=false} when the storage ports are implemented against something
 * else, an existing schema, another database, a remote service.
 *
 * <p>Runs after Hibernate's own auto-configuration so the entity manager it needs already exists.
 */
@AutoConfiguration(after = HibernateJpaAutoConfiguration.class)
@ConditionalOnClass({EntityManager.class, EntityManagerFactory.class})
@ConditionalOnProperty(prefix = "spring-auth.jpa", name = "enabled", havingValue = "true",
        matchIfMissing = true)
@Import(SpringAuthEntityScanRegistrar.class)
public class SpringAuthJpaAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(CredentialsStore.class)
    public CredentialsStore springAuthCredentialsStore(EntityManager entityManager) {
        return new JpaCredentialsStore(entityManager);
    }

    @Bean
    @ConditionalOnMissingBean(PasswordHistoryStore.class)
    public PasswordHistoryStore springAuthPasswordHistoryStore(EntityManager entityManager) {
        return new JpaPasswordHistoryStore(entityManager);
    }

    @Bean
    @ConditionalOnMissingBean(MfaCredentialStore.class)
    public MfaCredentialStore springAuthMfaCredentialStore(EntityManager entityManager) {
        return new JpaMfaCredentialStore(entityManager);
    }

    @Bean
    @ConditionalOnMissingBean(OtpChallengeStore.class)
    public OtpChallengeStore springAuthOtpChallengeStore(EntityManager entityManager) {
        return new JpaOtpChallengeStore(entityManager);
    }

    @Bean
    @ConditionalOnMissingBean(RefreshTokenStore.class)
    public RefreshTokenStore springAuthRefreshTokenStore(EntityManager entityManager) {
        return new JpaRefreshTokenStore(entityManager);
    }

    @Bean
    @ConditionalOnMissingBean(PasswordResetStore.class)
    public PasswordResetStore springAuthPasswordResetStore(EntityManager entityManager) {
        return new JpaPasswordResetStore(entityManager);
    }

    @Bean
    @ConditionalOnMissingBean(InvitationStore.class)
    public InvitationStore springAuthInvitationStore(EntityManager entityManager) {
        return new JpaInvitationStore(entityManager);
    }

    @Bean
    @ConditionalOnMissingBean(LoginHistoryStore.class)
    public LoginHistoryStore springAuthLoginHistoryStore(EntityManager entityManager) {
        return new JpaLoginHistoryStore(entityManager);
    }

    @Bean
    @ConditionalOnMissingBean(RoleStore.class)
    public RoleStore springAuthRoleStore(EntityManager entityManager) {
        return new JpaRoleStore(entityManager);
    }
}
