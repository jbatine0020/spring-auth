package io.github.springauth.jpa.store;

import io.github.springauth.core.model.Role;
import io.github.springauth.jpa.entity.AuthRoleEntity;
import java.time.Instant;
import java.util.Set;
import org.hibernate.cfg.Configuration;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class JpaRoleStoreSearchTest {
    @Test
    void filtersBeforePaginationAndFetchesOnlyTheSelectedPage() {
        try (var factory = new Configuration().addAnnotatedClass(AuthRoleEntity.class)
                .setProperty("hibernate.connection.url", "jdbc:h2:mem:role-search;MODE=PostgreSQL")
                .setProperty("hibernate.hbm2ddl.auto", "create-drop")
                .buildSessionFactory(); var session = factory.openSession()) {
            var tx = session.beginTransaction();
            var store = new JpaRoleStore(session);
            var at = Instant.now();
            store.save(Role.create("P1", "Alpha", "Comptabilité", Set.of("one"), at));
            store.save(Role.create("P2", "Beta", "Comptabilité", Set.of("two"), at));
            var archived = Role.create("P3", "Gamma", "Comptabilité", Set.of(), at);
            archived.archive(at); store.save(archived);
            session.flush(); session.clear();
            var second = store.search("comptabilité", "ACTIVE", 1, 1, "name", true);
            assertEquals(2, second.total());
            assertEquals(1, second.list().size());
            assertEquals("P2", second.list().getFirst().getCode());
            assertEquals(Set.of("two"), second.list().getFirst().getPermissions());
            assertTrue(store.search("%", null, 0, 10, "code", true).list().isEmpty());
            assertEquals(2, store.search("", "ACTIVE", 10, 1, "code", true).total());
            assertTrue(store.search("", "ACTIVE", 10, 1, "code", true).list().isEmpty());
            tx.rollback();
        }
    }
}
