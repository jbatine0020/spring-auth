package io.github.springauth.core.service;

import java.time.Duration;

import io.github.springauth.core.error.AuthErrorCodes;
import io.github.springauth.core.error.PasswordException;
import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.RequestContext;
import io.github.springauth.core.testsupport.AuthTestFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordServiceTest {

    private static final String PASSWORD = "Correct-Horse-42!";
    private static final String NEW_PASSWORD = "Another-Horse-77!";
    private static final RequestContext CONTEXT = RequestContext.of("10.0.0.1", "JUnit");

    private AuthTestFixture fixture;
    private AuthUser user;

    @BeforeEach
    void setUp() {
        fixture = new AuthTestFixture();
        user = AuthUser.builder(AuthUserId.of("user-1"), "alex@example.com")
                .email("alex@example.com")
                .phoneNumber("+2250700000000")
                .build();
        fixture.withUser(user, PASSWORD);
    }

    @Test
    void requiredChangeUsesAuthenticatedIdentityAndRevokesSessions() {
        fixture.passwordService.setPassword(user.id(), PASSWORD, true);
        AuthTokens session = fixture.sessionService.openSession(user);
        fixture.passwordService.completeRequiredPasswordChange(user.id(), NEW_PASSWORD);
        assertThat(fixture.sessionService.findSession(session.refreshToken()).orElseThrow().isRevoked()).isTrue();
        assertThat(fixture.loginService.login(user.login(), NEW_PASSWORD, CONTEXT).status())
                .isEqualTo(LoginResult.Status.AUTHENTICATED);
        assertThatThrownBy(() -> fixture.passwordService.completeRequiredPasswordChange(user.id(), PASSWORD))
                .isInstanceOf(PasswordException.class)
                .extracting(thrown -> ((PasswordException) thrown).getCode())
                .isEqualTo(AuthErrorCodes.PASSWORD_CHANGE_NOT_REQUIRED);
    }

    @Test
    void requiredChangePreservesPolicyAndPasswordHistory() {
        fixture.passwordService.setPassword(user.id(), PASSWORD, true);
        assertThatThrownBy(() -> fixture.passwordService.completeRequiredPasswordChange(user.id(), "short"))
                .isInstanceOf(PasswordException.class);
        assertThatThrownBy(() -> fixture.passwordService.completeRequiredPasswordChange(user.id(), PASSWORD))
                .isInstanceOf(PasswordException.class)
                .extracting(thrown -> ((PasswordException) thrown).getCode())
                .isEqualTo(AuthErrorCodes.PASSWORD_REUSED);
    }

    @Nested
    @DisplayName("self-service change")
    class Change {

        @Test
        @DisplayName("replaces the password and closes every session")
        void changeOwnPassword_revokesSessions() {
            AuthTokens session = fixture.sessionService.openSession(user);

            fixture.passwordService.changeOwnPassword(user.id(), PASSWORD, NEW_PASSWORD);

            assertThat(fixture.sessionService.findSession(session.refreshToken()).orElseThrow()
                    .isRevoked()).isTrue();
            assertThat(fixture.loginService.login(user.login(), NEW_PASSWORD, CONTEXT).status())
                    .isEqualTo(LoginResult.Status.AUTHENTICATED);
        }

        @Test
        @DisplayName("refuses a wrong current password")
        void changeOwnPassword_wrongCurrent_refused() {
            assertThatThrownBy(() -> fixture.passwordService
                    .changeOwnPassword(user.id(), "not-the-password", NEW_PASSWORD))
                    .isInstanceOf(PasswordException.class)
                    .extracting(thrown -> ((PasswordException) thrown).getCode())
                    .isEqualTo(AuthErrorCodes.PASSWORD_MISMATCH);
        }

        @Test
        @DisplayName("refuses a password that breaks the policy")
        void changeOwnPassword_weakPassword_refused() {
            assertThatThrownBy(() -> fixture.passwordService
                    .changeOwnPassword(user.id(), PASSWORD, "short"))
                    .isInstanceOf(PasswordException.class)
                    .extracting(thrown -> ((PasswordException) thrown).getCode())
                    .isEqualTo(AuthErrorCodes.PASSWORD_TOO_SHORT);
        }

        @Test
        @DisplayName("refuses a password the user already used")
        void changeOwnPassword_reused_refused() {
            fixture.passwordService.changeOwnPassword(user.id(), PASSWORD, NEW_PASSWORD);

            assertThatThrownBy(() -> fixture.passwordService
                    .changeOwnPassword(user.id(), NEW_PASSWORD, PASSWORD))
                    .isInstanceOf(PasswordException.class)
                    .extracting(thrown -> ((PasswordException) thrown).getCode())
                    .isEqualTo(AuthErrorCodes.PASSWORD_REUSED);
        }
    }

    @Nested
    @DisplayName("forgotten password")
    class Reset {

        @Test
        @DisplayName("hands the link and the code to the messenger")
        void requestReset_deliversBothFactors() {
            fixture.passwordService.requestReset(user.login(), CONTEXT);

            assertThat(fixture.messenger.passwordResetTokens).hasSize(1);
            assertThat(fixture.messenger.passwordResetOtps).hasSize(1);
            assertThat(fixture.messenger.passwordResetOtps.get(0)).hasSize(6).containsOnlyDigits();
        }

        @Test
        @DisplayName("stays silent for an unknown login")
        void requestReset_unknownLogin_doesNothingAndDoesNotThrow() {
            fixture.passwordService.requestReset("ghost@example.com", CONTEXT);

            assertThat(fixture.messenger.passwordResetTokens).isEmpty();
            assertThat(fixture.passwordResets.size()).isZero();
        }

        @Test
        @DisplayName("asking twice leaves a single working link")
        void requestReset_twice_keepsOnlyTheLatest() {
            fixture.passwordService.requestReset(user.login(), CONTEXT);
            String firstToken = fixture.messenger.passwordResetTokens.get(0);
            fixture.passwordService.requestReset(user.login(), CONTEXT);

            assertThat(fixture.passwordResets.size()).isEqualTo(1);
            assertThatThrownBy(() -> fixture.passwordService.confirmReset(
                    firstToken, fixture.messenger.passwordResetOtps.get(0), NEW_PASSWORD))
                    .isInstanceOf(PasswordException.class);
        }

        @Test
        @DisplayName("completes with the link and the code, and closes every session")
        void confirmReset_validFactors_setsThePassword() {
            AuthTokens session = fixture.sessionService.openSession(user);
            fixture.passwordService.requestReset(user.login(), CONTEXT);

            fixture.passwordService.confirmReset(
                    fixture.messenger.passwordResetTokens.get(0),
                    fixture.messenger.passwordResetOtps.get(0),
                    NEW_PASSWORD);

            assertThat(fixture.loginService.login(user.login(), NEW_PASSWORD, CONTEXT).status())
                    .isEqualTo(LoginResult.Status.AUTHENTICATED);
            assertThat(fixture.sessionService.findSession(session.refreshToken()).orElseThrow()
                    .isRevoked()).isTrue();
        }

        @Test
        @DisplayName("refuses the link alone when a code is required")
        void confirmReset_missingOtp_refused() {
            fixture.passwordService.requestReset(user.login(), CONTEXT);

            assertThatThrownBy(() -> fixture.passwordService.confirmReset(
                    fixture.messenger.passwordResetTokens.get(0), null, NEW_PASSWORD))
                    .isInstanceOf(PasswordException.class);
        }

        @Test
        @DisplayName("locks the link after too many wrong codes")
        void confirmReset_repeatedWrongOtp_locksTheLink() {
            fixture.passwordService.requestReset(user.login(), CONTEXT);
            String token = fixture.messenger.passwordResetTokens.get(0);
            String validOtp = fixture.messenger.passwordResetOtps.get(0);
            int maxAttempts = fixture.properties.getPasswordReset().getMaxAttempts();

            for (int attempt = 0; attempt < maxAttempts; attempt++) {
                assertThatThrownBy(() -> fixture.passwordService
                        .confirmReset(token, "000000", NEW_PASSWORD))
                        .isInstanceOf(PasswordException.class);
            }

            // Even the right code no longer works: a six-digit secret cannot be brute-forced.
            assertThatThrownBy(() -> fixture.passwordService.confirmReset(token, validOtp, NEW_PASSWORD))
                    .isInstanceOf(PasswordException.class)
                    .extracting(thrown -> ((PasswordException) thrown).getCode())
                    .isEqualTo(AuthErrorCodes.PASSWORD_RESET_LOCKED);
        }

        @Test
        @DisplayName("refuses an expired link")
        void confirmReset_expiredLink_refused() {
            fixture.passwordService.requestReset(user.login(), CONTEXT);
            String token = fixture.messenger.passwordResetTokens.get(0);
            String otp = fixture.messenger.passwordResetOtps.get(0);

            fixture.clock.advance(fixture.properties.getPasswordReset()
                    .getLinkTtl().plus(Duration.ofMinutes(1)));

            assertThatThrownBy(() -> fixture.passwordService.confirmReset(token, otp, NEW_PASSWORD))
                    .isInstanceOf(PasswordException.class)
                    .extracting(thrown -> ((PasswordException) thrown).getCode())
                    .isEqualTo(AuthErrorCodes.PASSWORD_RESET_EXPIRED);
        }

        @Test
        @DisplayName("refuses to reuse a link that already worked")
        void confirmReset_twice_refused() {
            fixture.passwordService.requestReset(user.login(), CONTEXT);
            String token = fixture.messenger.passwordResetTokens.get(0);
            String otp = fixture.messenger.passwordResetOtps.get(0);
            fixture.passwordService.confirmReset(token, otp, NEW_PASSWORD);

            assertThatThrownBy(() -> fixture.passwordService
                    .confirmReset(token, otp, "Third-Password-88!"))
                    .isInstanceOf(PasswordException.class);
        }

        @Test
        @DisplayName("a rejected password does not consume the link")
        void confirmReset_weakPassword_leavesTheLinkUsable() {
            fixture.passwordService.requestReset(user.login(), CONTEXT);
            String token = fixture.messenger.passwordResetTokens.get(0);
            String otp = fixture.messenger.passwordResetOtps.get(0);

            assertThatThrownBy(() -> fixture.passwordService.confirmReset(token, otp, "weak"))
                    .isInstanceOf(PasswordException.class);

            fixture.passwordService.confirmReset(token, otp, NEW_PASSWORD);
            assertThat(fixture.loginService.login(user.login(), NEW_PASSWORD, CONTEXT).status())
                    .isEqualTo(LoginResult.Status.AUTHENTICATED);
        }
    }

    @Nested
    @DisplayName("administrative set")
    class AdministrativeSet {

        @Test
        @DisplayName("forces a change at the next login")
        void setPassword_flagsTheAccount() {
            fixture.passwordService.setPassword(user.id(), "Temporary-Pass-9!", true);

            assertThat(fixture.loginService.login(user.login(), "Temporary-Pass-9!", CONTEXT)
                    .mustChangePassword()).isTrue();
        }

        @Test
        @DisplayName("closes every session of the target")
        void setPassword_revokesSessions() {
            AuthTokens session = fixture.sessionService.openSession(user);

            fixture.passwordService.setPassword(user.id(), "Temporary-Pass-9!", true);

            assertThat(fixture.sessionService.findSession(session.refreshToken()).orElseThrow()
                    .isRevoked()).isTrue();
        }

        @Test
        @DisplayName("unlocking clears a brute-force lock")
        void unlock_clearsTheLock() {
            int max = fixture.properties.getPassword().getMaxFailedAttempts();
            for (int attempt = 0; attempt < max; attempt++) {
                try {
                    fixture.loginService.login(user.login(), "wrong", CONTEXT);
                } catch (RuntimeException expected) {
                    // counted below
                }
            }

            fixture.passwordService.unlock(user.id());

            assertThat(fixture.loginService.login(user.login(), PASSWORD, CONTEXT).status())
                    .isEqualTo(LoginResult.Status.AUTHENTICATED);
        }
    }
}
