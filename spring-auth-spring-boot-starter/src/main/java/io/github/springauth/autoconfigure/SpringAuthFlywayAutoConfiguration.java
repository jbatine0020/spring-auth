package io.github.springauth.autoconfigure;

import javax.sql.DataSource;

import org.flywaydb.core.Flyway;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration;
import org.springframework.boot.jpa.autoconfigure.EntityManagerFactoryDependsOnPostProcessor;
import org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration;
import org.springframework.context.annotation.Bean;

/**
 * Runs the library's schema migration on its own Flyway instance.
 *
 * <p>Sharing the application's Flyway would break in two ways, both silently until the day they
 * do not:
 * <ul>
 *   <li><b>Version collision.</b> The library ships a {@code V1}, and so does almost every
 *       application. Two migrations with the same version in one history make Flyway refuse to
 *       start.</li>
 *   <li><b>Accidental pickup.</b> Flyway scans its locations recursively, so a migration placed
 *       under the conventional {@code db/migration} tree inside a jar is picked up by any
 *       application using the default configuration, whether it wanted it or not.</li>
 * </ul>
 *
 * <p>Hence a dedicated instance: its own location ({@code classpath:db/springauth/migration}), its
 * own history table ({@code flyway_schema_history_springauth}), and no interaction whatsoever with
 * the application's own migrations. Nothing to configure on the consuming side.
 *
 * <p>It runs before the entity manager is built, so the tables exist by the time Hibernate
 * validates its mapping against them.
 *
 * <p>Turn it off with {@code spring-auth.jpa.migrate=false} when the schema is managed elsewhere,
 * by a DBA-owned pipeline or a consolidated migration set. The SQL is readable inside the
 * {@code spring-auth-jpa} jar at that same location.
 */
// after DataSourceAutoConfiguration: the @ConditionalOnBean below is evaluated at parse time, and
// without that ordering the DataSource is not registered yet, the condition silently fails, the
// migration never runs, and Hibernate reports a missing table.
@AutoConfiguration(
        after = DataSourceAutoConfiguration.class,
        before = {FlywayAutoConfiguration.class, HibernateJpaAutoConfiguration.class})
@ConditionalOnClass(Flyway.class)
@ConditionalOnBean(DataSource.class)
@ConditionalOnProperty(prefix = "spring-auth.jpa", name = "migrate", havingValue = "true",
        matchIfMissing = true)
public class SpringAuthFlywayAutoConfiguration {

    /** Location of the library's migrations, deliberately outside the conventional tree. */
    public static final String MIGRATION_LOCATION = "classpath:db/springauth/migration";

    /** Dedicated history table, so the library's versions never mix with the application's. */
    public static final String HISTORY_TABLE = "flyway_schema_history_springauth";

    @Bean(initMethod = "migrate")
    @ConditionalOnMissingBean(name = "springAuthFlyway")
    public Flyway springAuthFlyway(DataSource dataSource) {
        return Flyway.configure()
                .dataSource(dataSource)
                .locations(MIGRATION_LOCATION)
                .table(HISTORY_TABLE)
                // The library's tables may be introduced into a database that already has a
                // history of its own; baselining keeps that from being read as a gap.  The
                // baseline must remain before the first shipped migration: Flyway's default
                // baseline version is 1, which would otherwise skip V1 on a fresh schema.
                .baselineOnMigrate(true)
                .baselineVersion("0")
                .load();
    }

    /**
     * Makes the entity manager wait for the migration.
     *
     * <p>Without it Hibernate can be built first and, under {@code ddl-auto: validate}, fail
     * against tables that are about to be created a moment later.
     */
    @Bean
    public static EntityManagerFactoryDependsOnPostProcessor springAuthFlywayDependsOnPostProcessor() {
        return new SpringAuthMigrationDependsOnPostProcessor();
    }

    static class SpringAuthMigrationDependsOnPostProcessor extends EntityManagerFactoryDependsOnPostProcessor {

        SpringAuthMigrationDependsOnPostProcessor() {
            super("springAuthFlyway");
        }
    }
}
