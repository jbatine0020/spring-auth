package io.github.springauth.core.service;

import java.time.Duration;

import io.github.springauth.core.error.AuthErrorCodes;
import io.github.springauth.core.error.AuthException;
import io.github.springauth.core.error.InvalidCredentialsException;
import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.AuthUserStatus;
import io.github.springauth.core.model.LoginFailureReason;
import io.github.springauth.core.model.MfaRequirement;
import io.github.springauth.core.model.MfaStatus;
import io.github.springauth.core.model.RequestContext;
import io.github.springauth.core.testsupport.AuthTestFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LoginServiceTest {

    private static final String PASSWORD = "Correct-Horse-42!";
    private static final RequestContext CONTEXT = RequestContext.of("10.0.0.1", "JUnit");

    private AuthTestFixture fixture;
    private AuthUser user;

    @BeforeEach
    void setUp() {
        fixture = new AuthTestFixture();
        user = AuthUser.builder(AuthUserId.of("user-1"), "alex@example.com")
                .email("alex@example.com")
                .build();
        fixture.withUser(user, PASSWORD);
    }

    @Nested
    @DisplayName("successful authentication")
    class Success {

        @Test
        @DisplayName("issues tokens when no second factor applies")
        void login_withoutMfa_returnsTokens() {
            LoginResult result = fixture.loginService.login(user.login(), PASSWORD, CONTEXT);

            assertThat(result.status()).isEqualTo(LoginResult.Status.AUTHENTICATED);
            assertThat(result.mfaStatus()).isEqualTo(MfaStatus.NOT_APPLICABLE);
            assertThat(result.tokens()).isNotNull();
            assertThat(result.tokens().accessToken()).isNotBlank();
            assertThat(result.tokens().refreshToken()).isNotBlank();
            assertThat(result.intermediateToken()).isNull();
        }

        @Test
        @DisplayName("records the success in the history")
        void login_recordsSuccess() {
            fixture.loginService.login(user.login(), PASSWORD, CONTEXT);

            assertThat(fixture.loginHistory.all()).hasSize(1);
            assertThat(fixture.loginHistory.all().get(0).isSuccessful()).isTrue();
            assertThat(fixture.loginHistory.all().get(0).getIpAddress()).isEqualTo("10.0.0.1");
            assertThat(fixture.events.successes).containsExactly("user-1");
        }

        @Test
        @DisplayName("clears a partial failure streak")
        void login_afterFailures_resetsCounter() {
            assertThatThrownBy(() -> fixture.loginService.login(user.login(), "wrong", CONTEXT))
                    .isInstanceOf(InvalidCredentialsException.class);

            fixture.loginService.login(user.login(), PASSWORD, CONTEXT);

            assertThat(fixture.credentials.findByUserId(user.id()).orElseThrow().getFailedAttempts())
                    .isZero();
        }

        @Test
        @DisplayName("flags a password an administrator forced to change")
        void login_mustChangePassword_isReported() {
            fixture.passwordService.setPassword(user.id(), "Temporary-Pass-9!", true);

            LoginResult result = fixture.loginService.login(user.login(), "Temporary-Pass-9!", CONTEXT);

            assertThat(result.mustChangePassword()).isTrue();
        }
    }

    @Nested
    @DisplayName("account enumeration resistance")
    class Enumeration {

        @Test
        @DisplayName("answers the same for an unknown login and a wrong password")
        void login_failures_areIndistinguishable() {
            AuthException unknownLogin = catchAuthException(
                    () -> fixture.loginService.login("nobody@example.com", PASSWORD, CONTEXT));
            AuthException wrongPassword = catchAuthException(
                    () -> fixture.loginService.login(user.login(), "wrong-password", CONTEXT));

            assertThat(unknownLogin.getCode()).isEqualTo(AuthErrorCodes.LOGIN_INVALID);
            assertThat(wrongPassword.getCode()).isEqualTo(unknownLogin.getCode());
            assertThat(wrongPassword.getMessage()).isEqualTo(unknownLogin.getMessage());
        }

        @Test
        @DisplayName("answers the same for a disabled account")
        void login_disabledAccount_looksLikeAnyOtherFailure() {
            AuthUser disabled = AuthUser.builder(AuthUserId.of("user-2"), "disabled@example.com")
                    .status(AuthUserStatus.DISABLED)
                    .build();
            fixture.withUser(disabled, PASSWORD);

            AuthException thrown = catchAuthException(
                    () -> fixture.loginService.login(disabled.login(), PASSWORD, CONTEXT));

            assertThat(thrown.getCode()).isEqualTo(AuthErrorCodes.LOGIN_INVALID);
            // The precise reason is kept for operators only.
            assertThat(fixture.events.failures).containsExactly(LoginFailureReason.DISABLED);
        }

        @Test
        @DisplayName("answers the same for an account that never redeemed its invitation")
        void login_pendingActivation_looksLikeAnyOtherFailure() {
            AuthUser invited = AuthUser.builder(AuthUserId.of("user-3"), "invited@example.com")
                    .status(AuthUserStatus.PENDING_ACTIVATION)
                    .build();
            fixture.withUser(invited, PASSWORD);

            AuthException thrown = catchAuthException(
                    () -> fixture.loginService.login(invited.login(), PASSWORD, CONTEXT));

            assertThat(thrown.getCode()).isEqualTo(AuthErrorCodes.LOGIN_INVALID);
            assertThat(fixture.events.failures).containsExactly(LoginFailureReason.NOT_ACTIVATED);
        }

        @Test
        @DisplayName("records an unknown login without inventing a user id")
        void login_unknownLogin_recordsWithoutUserId() {
            catchAuthException(() -> fixture.loginService.login("ghost@example.com", PASSWORD, CONTEXT));

            assertThat(fixture.loginHistory.all()).hasSize(1);
            assertThat(fixture.loginHistory.all().get(0).getUserId()).isNull();
            assertThat(fixture.events.failures).containsExactly(LoginFailureReason.UNKNOWN_LOGIN);
        }
    }

    @Nested
    @DisplayName("brute-force lock-out")
    class Lockout {

        @Test
        @DisplayName("locks the account after the configured number of failures")
        void login_repeatedFailures_locksAccount() {
            int max = fixture.properties.getPassword().getMaxFailedAttempts();

            for (int attempt = 0; attempt < max; attempt++) {
                catchAuthException(() -> fixture.loginService.login(user.login(), "wrong", CONTEXT));
            }

            assertThat(fixture.credentials.findByUserId(user.id()).orElseThrow()
                    .isLockedAt(fixture.clock.instant())).isTrue();
            assertThat(fixture.events.accountLocked).isEqualTo(1);
            assertThat(fixture.messenger.accountLockedAlerts).isEqualTo(1);
        }

        @Test
        @DisplayName("refuses the correct password while locked")
        void login_whileLocked_refusesEvenTheRightPassword() {
            int max = fixture.properties.getPassword().getMaxFailedAttempts();
            for (int attempt = 0; attempt < max; attempt++) {
                catchAuthException(() -> fixture.loginService.login(user.login(), "wrong", CONTEXT));
            }

            assertThatThrownBy(() -> fixture.loginService.login(user.login(), PASSWORD, CONTEXT))
                    .isInstanceOf(InvalidCredentialsException.class);
            assertThat(fixture.events.failures).contains(LoginFailureReason.LOCKED);
        }

        @Test
        @DisplayName("accepts the correct password once the lock expires")
        void login_afterLockWindow_succeeds() {
            int max = fixture.properties.getPassword().getMaxFailedAttempts();
            for (int attempt = 0; attempt < max; attempt++) {
                catchAuthException(() -> fixture.loginService.login(user.login(), "wrong", CONTEXT));
            }

            fixture.clock.advance(fixture.properties.getPassword()
                    .getLockoutDuration().plus(Duration.ofSeconds(1)));

            assertThat(fixture.loginService.login(user.login(), PASSWORD, CONTEXT).status())
                    .isEqualTo(LoginResult.Status.AUTHENTICATED);
        }

        @Test
        @DisplayName("counts the failure even though the call throws")
        void login_failedAttempt_isPersisted() {
            catchAuthException(() -> fixture.loginService.login(user.login(), "wrong", CONTEXT));

            // This is what noRollbackFor protects in a real transaction: without the counter
            // surviving the exception, lock-out would never accumulate.
            assertThat(fixture.credentials.findByUserId(user.id()).orElseThrow().getFailedAttempts())
                    .isEqualTo(1);
        }
    }

    @Nested
    @DisplayName("multi-factor branching")
    class MultiFactor {

        @Test
        @DisplayName("asks for enrolment when the user has no factor yet")
        void login_mfaRequiredButNotEnrolled_returnsEnrolmentToken() {
            AuthUser mfaUser = mfaUser();

            LoginResult result = fixture.loginService.login(mfaUser.login(), PASSWORD, CONTEXT);

            assertThat(result.status()).isEqualTo(LoginResult.Status.MFA_ENROLLMENT_REQUIRED);
            assertThat(result.mfaStatus()).isEqualTo(MfaStatus.NOT_CONFIGURED);
            assertThat(result.intermediateToken()).isNotBlank();
            assertThat(result.tokens()).as("no session before the factor exists").isNull();
        }

        @Test
        @DisplayName("asks for a code once the factor is confirmed")
        void login_mfaConfigured_returnsChallengeToken() {
            AuthUser mfaUser = mfaUser();
            enrolAndConfirm(mfaUser);

            LoginResult result = fixture.loginService.login(mfaUser.login(), PASSWORD, CONTEXT);

            assertThat(result.status()).isEqualTo(LoginResult.Status.MFA_CHALLENGE_REQUIRED);
            assertThat(result.mfaStatus()).isEqualTo(MfaStatus.CONFIGURED);
            assertThat(result.intermediateToken()).isNotBlank();
            assertThat(result.tokens()).isNull();
        }

        private AuthUser mfaUser() {
            AuthUser mfaUser = AuthUser.builder(AuthUserId.of("user-mfa"), "mfa@example.com")
                    .email("mfa@example.com")
                    .mfaRequirement(MfaRequirement.REQUIRED)
                    .build();
            fixture.withUser(mfaUser, PASSWORD);
            return mfaUser;
        }

        private void enrolAndConfirm(AuthUser mfaUser) {
            LoginResult first = fixture.loginService.login(mfaUser.login(), PASSWORD, CONTEXT);
            fixture.mfaService.startEnrollment(first.intermediateToken());
            fixture.mfaService.confirmEnrollment(first.intermediateToken(),
                    fixture.currentTotpCode(mfaUser));
        }
    }

    @Nested
    @DisplayName("application veto")
    class Guard {

        @Test
        @DisplayName("runs after the password check, so it cannot be probed anonymously")
        void loginGuard_refusesAfterPasswordCheck() {
            fixture.withLoginGuard((checked, context) -> {
                throw new InvalidCredentialsException();
            });

            assertThatThrownBy(() -> fixture.loginService.login(user.login(), PASSWORD, CONTEXT))
                    .isInstanceOf(InvalidCredentialsException.class);
            // The password was verified before the veto ran, so the counter was reset, not raised.
            assertThat(fixture.credentials.findByUserId(user.id()).orElseThrow().getFailedAttempts())
                    .isZero();
        }

        @Test
        @DisplayName("issues nothing when it refuses")
        void loginGuard_refuses_noSessionOpened() {
            fixture.withLoginGuard((checked, context) -> {
                throw new InvalidCredentialsException();
            });

            catchAuthException(() -> fixture.loginService.login(user.login(), PASSWORD, CONTEXT));

            assertThat(fixture.refreshTokens.size()).isZero();
        }
    }

    private static AuthException catchAuthException(Runnable action) {
        try {
            action.run();
            throw new AssertionError("expected an AuthException");
        } catch (AuthException ex) {
            return ex;
        }
    }
}
