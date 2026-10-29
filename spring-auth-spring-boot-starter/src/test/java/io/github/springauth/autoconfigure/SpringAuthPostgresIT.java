package io.github.springauth.autoconfigure;

import io.github.springauth.core.error.InvalidCredentialsException;
import io.github.springauth.core.error.SessionException;
import io.github.springauth.core.error.MfaException;
import io.github.springauth.core.crypto.TotpGenerator;
import io.github.springauth.core.identity.ApplicationUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.OtpChallenge;
import io.github.springauth.core.model.OtpChannel;
import io.github.springauth.core.model.RequestContext;
import io.github.springauth.core.model.WebAuthnCredential;
import io.github.springauth.core.port.CredentialsStore;
import io.github.springauth.core.port.OtpChallengeStore;
import io.github.springauth.core.service.LoginService;
import io.github.springauth.core.service.MfaService;
import io.github.springauth.core.service.PasswordService;
import io.github.springauth.core.service.RoleService;
import io.github.springauth.core.service.SessionService;
import io.github.springauth.jpa.store.JpaWebAuthnCredentialStore;
import io.github.springauth.jpa.store.JpaApplicationUserStore;
import jakarta.persistence.EntityManager;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import javax.sql.DataSource;
import java.time.Duration;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Runs the HTTP starter suite and database-specific contracts on a migrated PostgreSQL schema. */
@Tag("postgres")
@Testcontainers
@Import(SpringAuthPostgresIT.HostMigrationConfiguration.class)
class SpringAuthPostgresIT extends SpringAuthStarterIT {

    private static final AuthUserId USER = AuthUserId.of("11111111-1111-1111-1111-111111111111");
    private static final String PASSWORD = "Correct-Horse-42!";

    @Container
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.4")
            .withDatabaseName("spring_auth_integration")
            .withUsername("spring_auth_test")
            .withPassword(UUID.randomUUID().toString())
            .withInitScript("postgres/init.sql");

    @DynamicPropertySource
    static void postgresProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.datasource.hikari.schema", () -> "spring_auth_test");
        registry.add("spring.jpa.properties.hibernate.default_schema", () -> "spring_auth_test");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        registry.add("spring-auth.jpa.migrate", () -> "true");
    }

    @Autowired JdbcTemplate jdbc;
    @Autowired EntityManager entityManager;
    @Autowired PlatformTransactionManager transactionManager;
    @Autowired LoginService login;
    @Autowired SessionService sessions;
    @Autowired RoleService roles;
    @Autowired CredentialsStore credentials;
    @Autowired OtpChallengeStore challenges;
    @Autowired MfaService mfa;
    @Autowired PasswordService passwords;
    @Autowired Clock clock;
    @Autowired @Qualifier("springAuthFlyway") Flyway authFlyway;
    @Autowired @Qualifier("hostFlyway") Flyway hostFlyway;

    @Test
    void migrationsApplyAllVersionsAndRemainSeparateFromConsumerHistory() {
        assertThat(jdbc.queryForObject("select version()", String.class)).contains("PostgreSQL 17.4");
        assertThat(jdbc.queryForObject("select current_schema()", String.class))
                .isEqualTo("spring_auth_test");
        assertThat(authFlyway.info().current().getVersion().getVersion()).isEqualTo("13");
        assertThat(hostFlyway.info().current().getVersion().getVersion()).isEqualTo("1");
        assertThat(jdbc.queryForObject("select label from host_application_marker where id=1", String.class))
                .isEqualTo("consumer migration");
        authFlyway.validate();
        hostFlyway.validate();
        assertThat(authFlyway.migrate().migrationsExecuted).isZero();
        assertThat(hostFlyway.migrate().migrationsExecuted).isZero();
        assertThat(roles.get("AUTH_ADMIN").getPermissions()).contains("auth:audit:read");
    }

    @Test
    void generatedProfileCodesAreUniqueUnderConcurrentTransactions() throws Exception {
        String name = "Integration profile " + UUID.randomUUID();
        List<String> codes = race(() -> roles.createGenerated(name, null, Set.of("records:read")).getCode());
        assertThat(codes).doesNotHaveDuplicates().allMatch(code -> code.matches("PROF-\\d{4,}"));
        for (String code : codes) assertThat(roles.get(code).getPermissions()).containsExactly("records:read");
    }

    @Test
    void failedPasswordAttemptsCommitEvenWhenLoginThrows() {
        assertThatThrownBy(() -> login.login("alex@example.com", "incorrect", RequestContext.empty()))
                .isInstanceOf(InvalidCredentialsException.class);
        Integer failed = new TransactionTemplate(transactionManager).execute(status ->
                credentials.findByUserId(USER).orElseThrow().getFailedAttempts());
        assertThat(failed).isEqualTo(1);
        login.login("alex@example.com", PASSWORD, RequestContext.empty());
    }

    @Test
    void refreshedTokenReplayPermanentlyRevokesTheSuccessor() {
        var first = login.login("alex@example.com", PASSWORD, RequestContext.empty()).tokens();
        var next = sessions.refresh(first.refreshToken(), RequestContext.empty());
        assertThatThrownBy(() -> sessions.refresh(first.refreshToken(), RequestContext.empty()))
                .isInstanceOf(SessionException.class);
        assertThat(sessions.findSession(next.refreshToken()).orElseThrow().isRevoked()).isTrue();
    }

    @Test
    void concurrentRefreshDoesNotCreateTwoSuccessors() throws Exception {
        var first = login.login("alex@example.com", PASSWORD, RequestContext.empty()).tokens();
        List<Boolean> outcomes = race(() -> {
            try {
                sessions.refresh(first.refreshToken(), RequestContext.empty());
                return true;
            } catch (SessionException expected) {
                return false;
            }
        });
        assertThat(outcomes).containsExactlyInAnyOrder(true, false);
    }

    @Test
    void otpRowLockAllowsOnlyOneConsumption() throws Exception {
        AuthUserId user = AuthUserId.of(UUID.randomUUID());
        var tx = new TransactionTemplate(transactionManager);
        tx.executeWithoutResult(status -> challenges.save(OtpChallenge.issue(user, OtpChannel.EMAIL,
                "test-hash", "test-fingerprint", "u***@example.test", Instant.now(), Duration.ofMinutes(3))));
        List<Boolean> outcomes = race(() -> tx.execute(status -> {
            var challenge = challenges.findForUpdate(user, OtpChannel.EMAIL).orElseThrow();
            if (!challenge.canVerifyAt(Instant.now())) return false;
            challenge.consume(Instant.now());
            challenges.save(challenge);
            return true;
        }));
        assertThat(outcomes).containsExactlyInAnyOrder(true, false);
    }

    @Test
    void webAuthnBinaryKeyUsesByteaAndSurvivesTransactionBoundary() {
        String id = UUID.randomUUID().toString();
        byte[] bytes = new byte[]{0, 1, 127, (byte) 128, (byte) 255};
        var tx = new TransactionTemplate(transactionManager);
        var store = new JpaWebAuthnCredentialStore(entityManager);
        tx.executeWithoutResult(status -> store.save(new WebAuthnCredential(id, USER, bytes, 0,
                "Integration key", Instant.now(), null)));
        var restored = tx.execute(status -> store.findByCredentialId(id).orElseThrow());
        assertThat(restored.publicKey()).containsExactly(bytes);
        assertThat(jdbc.queryForObject("select pg_typeof(public_key)::text from auth_webauthn_credentials "
                + "where credential_id=?", String.class, id)).isEqualTo("bytea");
    }

    @Test
    void applicationIdentityAttributesAndRolesRoundTripOnPostgres() {
        UUID id = UUID.randomUUID();
        Instant now = Instant.now();
        var user = new ApplicationUser(id, "user-" + id, id + "@example.test", null,
                "Utilisateur Élodie", "Utilisateur", "Élodie", "local:" + id,
                "Service local", "Agent", "ACTIVE", "NONE", Set.of("AUTH_ADMIN"), now, now);
        var store = new JpaApplicationUserStore(entityManager);
        var tx = new TransactionTemplate(transactionManager);
        tx.executeWithoutResult(status -> store.save(user));
        var restored = tx.execute(status -> store.findById(id).orElseThrow());
        assertThat(restored.nom()).isEqualTo("Utilisateur");
        assertThat(restored.prenom()).isEqualTo("Élodie");
        assertThat(restored.roleCodes()).containsExactly("AUTH_ADMIN");
    }

    @Test
    void totpEnrollmentPersistsAndConcurrentCodeUseSucceedsOnlyOnce() throws Exception {
        var id = AuthUserId.of("22222222-2222-2222-2222-222222222222");
        passwords.setPassword(id, PASSWORD, false);
        var enrollmentLogin = login.login("mfa@example.com", PASSWORD, RequestContext.empty());
        var enrollment = mfa.startEnrollment(enrollmentLogin.intermediateToken());
        var generator = new TotpGenerator();
        mfa.confirmEnrollment(enrollmentLogin.intermediateToken(),
                generator.codeAt(enrollment.base32Secret(), clock.instant(), 6));
        assertThat(jdbc.queryForObject("select encrypted_secret from auth_mfa_credentials where user_id=?",
                String.class, id.value())).doesNotContain(enrollment.base32Secret());
        var challenge = login.login("mfa@example.com", PASSWORD, RequestContext.empty());
        String nextCode = generator.codeAt(enrollment.base32Secret(), clock.instant().plusSeconds(30), 6);
        List<Boolean> outcomes = race(() -> {
            try {
                mfa.verifyForLogin(challenge.intermediateToken(), nextCode, RequestContext.empty());
                return true;
            } catch (MfaException expected) {
                return false;
            }
        });
        assertThat(outcomes).containsExactlyInAnyOrder(true, false);
    }

    @Test
    void auditTextSupportsLargeUnicodePayloads() {
        UUID id = UUID.randomUUID();
        String details = "{\"note\":\"" + "Événement de sécurité ".repeat(1500) + "\"}";
        jdbc.update("insert into auth_audit_events (id, audit_reference, occurred_at, module_name, "
                        + "action_name, result_code, severity_code, details_json, created_at) "
                        + "values (?, ?, current_timestamp, 'AUTH', 'TEST', 'SUCCESS', 'STANDARD', ?, current_timestamp)",
                id, "TEST-" + id, details);
        assertThat(jdbc.queryForObject("select details_json from auth_audit_events where id=?", String.class, id))
                .isEqualTo(details);
    }

    private static <T> List<T> race(Callable<T> operation) throws Exception {
        var ready = new CountDownLatch(2);
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            Callable<T> action = () -> {
                ready.countDown();
                if (!start.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("Race did not start");
                return operation.call();
            };
            var first = executor.submit(action);
            var second = executor.submit(action);
            if (!ready.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("Workers did not start");
            start.countDown();
            return List.of(first.get(30, TimeUnit.SECONDS), second.get(30, TimeUnit.SECONDS));
        }
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class HostMigrationConfiguration {
        @Bean(initMethod = "migrate")
        Flyway hostFlyway(DataSource source) {
            return Flyway.configure().dataSource(source).locations("classpath:postgres/host")
                    .table("flyway_schema_history_host").baselineOnMigrate(true).baselineVersion("0").load();
        }
    }
}
