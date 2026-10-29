package io.github.springauth.core.model;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RefreshTokenTest {

    private static final AuthUserId USER = AuthUserId.of("user-1");
    private static final Instant NOW = Instant.parse("2026-03-01T10:00:00Z");
    private static final Duration TTL = Duration.ofDays(30);

    @Test
    @DisplayName("a new session opens its own family")
    void issueNewSession_startsANewFamily() {
        RefreshToken first = RefreshToken.issueNewSession(USER, "hash-1", TTL, NOW);
        RefreshToken second = RefreshToken.issueNewSession(USER, "hash-2", TTL, NOW);

        assertThat(first.getFamilyId()).isNotEqualTo(second.getFamilyId());
        assertThat(first.isActiveAt(NOW)).isTrue();
    }

    @Test
    @DisplayName("a refresh stays inside the family of the token it replaces")
    void issueWithinFamily_keepsTheFamily() {
        RefreshToken original = RefreshToken.issueNewSession(USER, "hash-1", TTL, NOW);

        RefreshToken successor = RefreshToken.issueWithinFamily(
                USER, original.getFamilyId(), "hash-2", TTL, NOW);

        assertThat(successor.getFamilyId()).isEqualTo(original.getFamilyId());
    }

    @Test
    @DisplayName("rotation revokes the token and links it to its successor")
    void rotateTo_revokesAndLinks() {
        RefreshToken original = RefreshToken.issueNewSession(USER, "hash-1", TTL, NOW);
        UUID successorId = UUID.randomUUID();

        original.rotateTo(successorId, NOW);

        assertThat(original.isRevoked()).isTrue();
        assertThat(original.isActiveAt(NOW)).isFalse();
        assertThat(original.getReplacedBy()).isEqualTo(successorId);
    }

    @Test
    @DisplayName("a token cannot be rotated twice")
    void rotateTo_alreadyRevoked_throws() {
        RefreshToken original = RefreshToken.issueNewSession(USER, "hash-1", TTL, NOW);
        original.rotateTo(UUID.randomUUID(), NOW);

        assertThatThrownBy(() -> original.rotateTo(UUID.randomUUID(), NOW))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("revocation is idempotent and keeps the first instant")
    void revoke_isIdempotent() {
        RefreshToken token = RefreshToken.issueNewSession(USER, "hash-1", TTL, NOW);

        token.revoke(NOW);
        token.revoke(NOW.plusSeconds(60));

        assertThat(token.getRevokedAt()).isEqualTo(NOW);
    }

    @Test
    @DisplayName("expires exactly at its deadline")
    void isActiveAt_expiry_isExclusive() {
        RefreshToken token = RefreshToken.issueNewSession(USER, "hash-1", TTL, NOW);

        assertThat(token.isActiveAt(NOW.plus(TTL).minusSeconds(1))).isTrue();
        assertThat(token.isActiveAt(NOW.plus(TTL))).isFalse();
        assertThat(token.isExpiredAt(NOW.plus(TTL))).isTrue();
    }
}
