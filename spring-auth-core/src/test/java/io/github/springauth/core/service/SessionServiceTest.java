package io.github.springauth.core.service;

import java.time.Duration;

import io.github.springauth.core.error.AuthErrorCodes;
import io.github.springauth.core.error.SessionException;
import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.AuthUserStatus;
import io.github.springauth.core.model.RefreshToken;
import io.github.springauth.core.model.RequestContext;
import io.github.springauth.core.testsupport.AuthTestFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SessionServiceTest {

    private static final RequestContext CONTEXT = RequestContext.of("10.0.0.1", "JUnit");

    private AuthTestFixture fixture;
    private AuthUser user;

    @BeforeEach
    void setUp() {
        fixture = new AuthTestFixture();
        user = AuthUser.builder(AuthUserId.of("user-1"), "alex@example.com")
                .email("alex@example.com")
                .build();
        fixture.withUser(user, "Correct-Horse-42!");
    }

    @Test
    @DisplayName("a refresh returns a new pair and revokes the presented token")
    void refresh_rotatesTheToken() {
        AuthTokens initial = fixture.sessionService.openSession(user);

        AuthTokens refreshed = fixture.sessionService.refresh(initial.refreshToken(), CONTEXT);

        assertThat(refreshed.refreshToken()).isNotEqualTo(initial.refreshToken());
        assertThat(refreshed.accessToken()).isNotBlank();
        RefreshToken presented = fixture.sessionService.findSession(initial.refreshToken()).orElseThrow();
        assertThat(presented.isRevoked()).isTrue();
        assertThat(presented.getReplacedBy()).isNotNull();
    }

    @Test
    @DisplayName("the successor stays in the same family")
    void refresh_keepsTheFamily() {
        AuthTokens initial = fixture.sessionService.openSession(user);
        AuthTokens refreshed = fixture.sessionService.refresh(initial.refreshToken(), CONTEXT);

        RefreshToken first = fixture.sessionService.findSession(initial.refreshToken()).orElseThrow();
        RefreshToken second = fixture.sessionService.findSession(refreshed.refreshToken()).orElseThrow();

        assertThat(second.getFamilyId()).isEqualTo(first.getFamilyId());
    }

    @Test
    @DisplayName("replaying a rotated token burns the whole family")
    void refresh_replay_invalidatesTheFamily() {
        AuthTokens initial = fixture.sessionService.openSession(user);
        AuthTokens refreshed = fixture.sessionService.refresh(initial.refreshToken(), CONTEXT);

        // The attacker presents the token the legitimate client already rotated away.
        assertThatThrownBy(() -> fixture.sessionService.refresh(initial.refreshToken(), CONTEXT))
                .isInstanceOf(SessionException.class)
                .extracting(thrown -> ((SessionException) thrown).getCode())
                .isEqualTo(AuthErrorCodes.REFRESH_TOKEN_REPLAY);
        assertThat(fixture.events.replayDetected).isEqualTo(1);

        // Both parties are logged out: the token the victim currently holds was revoked with the
        // rest of the family, so their next refresh fails too and forces a re-authentication.
        assertThatThrownBy(() -> fixture.sessionService.refresh(refreshed.refreshToken(), CONTEXT))
                .isInstanceOf(SessionException.class);
    }

    @Test
    @DisplayName("a replay also stamps an access-token revocation")
    void refresh_replay_stampsAccessRevocation() {
        AuthTokens initial = fixture.sessionService.openSession(user);
        fixture.sessionService.refresh(initial.refreshToken(), CONTEXT);

        assertThatThrownBy(() -> fixture.sessionService.refresh(initial.refreshToken(), CONTEXT))
                .isInstanceOf(SessionException.class);

        assertThat(fixture.revocations.hasStampFor(user.id())).isTrue();
    }

    @Test
    @DisplayName("an unknown token is refused")
    void refresh_unknownToken_refused() {
        assertThatThrownBy(() -> fixture.sessionService.refresh("not-a-token", CONTEXT))
                .isInstanceOf(SessionException.class)
                .extracting(thrown -> ((SessionException) thrown).getCode())
                .isEqualTo(AuthErrorCodes.REFRESH_TOKEN_INVALID);
    }

    @Test
    @DisplayName("an expired token is refused")
    void refresh_expiredToken_refused() {
        AuthTokens initial = fixture.sessionService.openSession(user);

        fixture.clock.advance(fixture.properties.getSession().getRefreshTtl().plus(Duration.ofDays(1)));

        assertThatThrownBy(() -> fixture.sessionService.refresh(initial.refreshToken(), CONTEXT))
                .isInstanceOf(SessionException.class);
    }

    @Test
    @DisplayName("a session cannot be refreshed once the account is disabled")
    void refresh_disabledUser_refusedAndSessionsClosed() {
        AuthTokens initial = fixture.sessionService.openSession(user);
        fixture.directory.replace(AuthUser.builder(user.id(), user.login())
                .status(AuthUserStatus.DISABLED)
                .build());

        assertThatThrownBy(() -> fixture.sessionService.refresh(initial.refreshToken(), CONTEXT))
                .isInstanceOf(SessionException.class);

        assertThat(fixture.sessionService.findSession(initial.refreshToken()).orElseThrow().isRevoked())
                .isTrue();
    }

    @Test
    @DisplayName("logout revokes the presented session and is idempotent")
    void logout_revokesTheSession() {
        AuthTokens initial = fixture.sessionService.openSession(user);

        fixture.sessionService.logout(initial.refreshToken());
        fixture.sessionService.logout(initial.refreshToken());
        fixture.sessionService.logout("unknown-token");

        assertThat(fixture.sessionService.findSession(initial.refreshToken()).orElseThrow().isRevoked())
                .isTrue();
    }

    @Test
    @DisplayName("revoking every session closes them all and stamps the access revocation")
    void revokeAllSessions_closesEverything() {
        fixture.sessionService.openSession(user);
        fixture.sessionService.openSession(user);

        int revoked = fixture.sessionService.revokeAllSessions(user.id());

        assertThat(revoked).isEqualTo(2);
        assertThat(fixture.refreshTokens.all()).allMatch(RefreshToken::isRevoked);
        assertThat(fixture.revocations.hasStampFor(user.id())).isTrue();
    }
}
