package io.github.springauth.core.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import io.github.springauth.core.error.SessionUnavailableException;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.ServerSession;
import io.github.springauth.core.port.ServerSessionStore;
import org.junit.jupiter.api.Test;

class ServerSessionServiceTest {

    @Test
    void opensAndTouchesSessionWithinIdleAndAbsoluteLimits() {
        var clock = Clock.fixed(Instant.parse("2026-08-11T00:00:00Z"), ZoneOffset.UTC);
        var store = new FakeStore();
        var service = new ServerSessionService(store, clock, Duration.ofMinutes(30), Duration.ofHours(8));

        ServerSession session = service.open(AuthUserId.of("user-1"));
        ServerSession active = service.requireActive(session.id());

        assertThat(active.userId().value()).isEqualTo("user-1");
        assertThat(active.revoked()).isFalse();
        assertThat(active.absoluteExpiresAt()).isEqualTo(Instant.parse("2026-08-11T08:00:00Z"));
    }

    @Test
    void refusesWhenTheSessionStoreFails() {
        ServerSessionStore failing = new ServerSessionStore() {
            public ServerSession create(AuthUserId userId, Instant now, Instant expires) {
                throw new IllegalStateException("redis down");
            }
            public Optional<ServerSession> find(UUID id) { throw new IllegalStateException("redis down"); }
            public ServerSession save(ServerSession session) { throw new IllegalStateException("redis down"); }
            public int revokeAllForUser(AuthUserId userId, Instant now) { throw new IllegalStateException("redis down"); }
        };
        var service = new ServerSessionService(failing, Clock.systemUTC(),
                Duration.ofMinutes(30), Duration.ofHours(8));

        assertThatThrownBy(() -> service.open(AuthUserId.of("user-1")))
                .isInstanceOf(SessionUnavailableException.class)
                .hasMessage("session backend unavailable");
        assertThatThrownBy(() -> service.requireActive(UUID.randomUUID()))
                .isInstanceOf(SessionUnavailableException.class);
    }

    private static final class FakeStore implements ServerSessionStore {
        private final Map<UUID, ServerSession> sessions = new HashMap<>();

        public ServerSession create(AuthUserId userId, Instant now, Instant expires) {
            ServerSession session = new ServerSession(UUID.randomUUID(), userId, now, now, expires, false);
            sessions.put(session.id(), session);
            return session;
        }

        public Optional<ServerSession> find(UUID id) { return Optional.ofNullable(sessions.get(id)); }

        public ServerSession save(ServerSession session) {
            sessions.put(session.id(), session);
            return session;
        }

        public int revokeAllForUser(AuthUserId userId, Instant now) {
            int count = 0;
            for (ServerSession session : sessions.values()) {
                if (session.userId().equals(userId) && !session.revoked()) {
                    sessions.put(session.id(), session.asRevoked());
                    count++;
                }
            }
            return count;
        }
    }
}
