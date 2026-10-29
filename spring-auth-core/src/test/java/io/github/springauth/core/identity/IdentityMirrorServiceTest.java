package io.github.springauth.core.identity;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import io.github.springauth.core.identity.IdentityAuthenticationResult;
import io.github.springauth.core.identity.IdentityMirrorService;
import io.github.springauth.core.identity.IdentityMirrorStore;
import io.github.springauth.core.identity.IdentityProvider;
import io.github.springauth.core.identity.IdentityProviderException;
import io.github.springauth.core.identity.IdentityUserMirror;
import org.junit.jupiter.api.Test;

class IdentityMirrorServiceTest {

    @Test
    void createsMirrorWithNoProviderRolesAndPreservesLocalRolesOnSync() throws Exception {
        var store = new InMemoryMirrorStore();
        var service = new IdentityMirrorService(store,
                Clock.fixed(Instant.parse("2026-08-11T00:00:00Z"), ZoneOffset.UTC));
        IdentityProvider provider = new IdentityProvider() {
            public String providerId() { return "test-provider"; }
            public IdentityAuthenticationResult authenticate(String login, char[] password)
                    throws IdentityProviderException { return null; }
        };

        var first = service.synchronize(provider,
                new IdentityAuthenticationResult("subject-1", "ndiaye", "A. N'Diaye",
                        "a@example.test", Map.of("department", "finance")));
        store.roles = Set.of("CHECKER");
        var second = service.synchronize(provider,
                new IdentityAuthenticationResult("subject-1", "ndiaye.new", "A. N'Diaye",
                        "new@example.test", Map.of()));

        assertThat(first.roleCodes()).isEmpty();
        assertThat(second.login()).isEqualTo("ndiaye.new");
        assertThat(second.email()).isEqualTo("new@example.test");
        assertThat(second.roleCodes()).containsExactly("CHECKER");
    }

    private static final class InMemoryMirrorStore implements IdentityMirrorStore {
        private final Map<String, IdentityUserMirror> values = new HashMap<>();
        private Set<String> roles = Set.of();

        public Optional<IdentityUserMirror> find(String providerId, String externalSubject) {
            return Optional.ofNullable(values.get(providerId + ":" + externalSubject));
        }

        public Optional<IdentityUserMirror> findByLogin(String login) {
            return values.values().stream().filter(v -> login.equalsIgnoreCase(v.login())).findFirst();
        }
        public Optional<IdentityUserMirror> findById(java.util.UUID id) {
            return Optional.ofNullable(values.values().stream().filter(v -> id.equals(v.id())).findFirst().orElse(null));
        }

        public IdentityUserMirror save(IdentityUserMirror mirror) {
            IdentityUserMirror saved = mirror.roleCodes().isEmpty() && !roles.isEmpty()
                    ? new IdentityUserMirror(mirror.id(), mirror.providerId(), mirror.externalSubject(),
                    mirror.login(), mirror.displayName(), mirror.email(), mirror.status(), mirror.mfaRequired(), roles,
                    mirror.createdAt(), mirror.updatedAt()) : mirror;
            values.put(saved.providerId() + ":" + saved.externalSubject(), saved);
            return saved;
        }
    }
}
