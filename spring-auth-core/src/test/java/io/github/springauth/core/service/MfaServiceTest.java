package io.github.springauth.core.service;

import java.time.Duration;

import io.github.springauth.core.error.AuthErrorCodes;
import io.github.springauth.core.error.MfaException;
import io.github.springauth.core.jwt.TokenPurpose;
import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.MfaRequirement;
import io.github.springauth.core.model.MfaStatus;
import io.github.springauth.core.model.RequestContext;
import io.github.springauth.core.testsupport.AuthTestFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MfaServiceTest {

    private static final String PASSWORD = "Correct-Horse-42!";
    private static final RequestContext CONTEXT = RequestContext.of("10.0.0.1", "JUnit");

    private AuthTestFixture fixture;
    private AuthUser user;

    @BeforeEach
    void setUp() {
        fixture = new AuthTestFixture();
        user = AuthUser.builder(AuthUserId.of("user-mfa"), "mfa@example.com")
                .email("mfa@example.com")
                .mfaRequirement(MfaRequirement.REQUIRED)
                .build();
        fixture.withUser(user, PASSWORD);
    }

    @Test
    @DisplayName("enrolment returns a secret and an otpauth URI")
    void startEnrollment_returnsEnrolmentMaterial() {
        String enrolmentToken = enrolmentToken();

        TotpEnrollment enrollment = fixture.mfaService.startEnrollment(enrolmentToken);

        assertThat(enrollment.base32Secret()).hasSize(32);
        assertThat(enrollment.otpauthUri()).startsWith("otpauth://totp/");
        assertThat(enrollment.account()).isEqualTo("mfa@example.com");
    }

    @Test
    @DisplayName("an enrolled but unconfirmed factor does not count")
    void startEnrollment_doesNotConfirm() {
        fixture.mfaService.startEnrollment(enrolmentToken());

        assertThat(fixture.mfaService.statusOf(user)).isEqualTo(MfaStatus.NOT_CONFIGURED);
    }

    @Test
    @DisplayName("confirming with a valid code opens a session")
    void confirmEnrollment_validCode_opensSession() {
        String enrolmentToken = enrolmentToken();
        fixture.mfaService.startEnrollment(enrolmentToken);

        AuthTokens tokens = fixture.mfaService.confirmEnrollment(
                enrolmentToken, fixture.currentTotpCode(user));

        assertThat(tokens.accessToken()).isNotBlank();
        assertThat(tokens.refreshToken()).isNotBlank();
        assertThat(fixture.mfaService.statusOf(user)).isEqualTo(MfaStatus.CONFIGURED);
        assertThat(fixture.events.mfaEnrolled).isEqualTo(1);
    }

    @Test
    @DisplayName("confirming with a wrong code is refused")
    void confirmEnrollment_wrongCode_refused() {
        String enrolmentToken = enrolmentToken();
        fixture.mfaService.startEnrollment(enrolmentToken);

        assertThatThrownBy(() -> fixture.mfaService.confirmEnrollment(enrolmentToken, "000000"))
                .isInstanceOf(MfaException.class)
                .extracting(thrown -> ((MfaException) thrown).getCode())
                .isEqualTo(AuthErrorCodes.MFA_INVALID_CODE);
    }

    @Test
    @DisplayName("a challenge token cannot be used to start an enrolment")
    void startEnrollment_withChallengeToken_refused() {
        enrolAndConfirm();
        LoginResult login = fixture.loginService.login(user.login(), PASSWORD, CONTEXT);

        // The token is valid and correctly signed, but minted for the verification step.
        assertThatThrownBy(() -> fixture.mfaService.startEnrollment(login.intermediateToken()))
                .isInstanceOf(MfaException.class)
                .extracting(thrown -> ((MfaException) thrown).getCode())
                .isEqualTo(AuthErrorCodes.MFA_CHALLENGE_INVALID);
    }

    @Test
    @DisplayName("verification completes a login")
    void verifyForLogin_validCode_opensSession() {
        enrolAndConfirm();
        LoginResult login = fixture.loginService.login(user.login(), PASSWORD, CONTEXT);
        // Move past the step used at enrolment so the counter guard accepts a fresh code.
        fixture.clock.advance(Duration.ofSeconds(30));

        AuthTokens tokens = fixture.mfaService.verifyForLogin(
                login.intermediateToken(), fixture.currentTotpCode(user), CONTEXT);

        assertThat(tokens.accessToken()).isNotBlank();
    }

    @Test
    @DisplayName("the same code cannot be used twice")
    void verifyForLogin_replayedCode_refused() {
        enrolAndConfirm();
        LoginResult login = fixture.loginService.login(user.login(), PASSWORD, CONTEXT);
        fixture.clock.advance(Duration.ofSeconds(30));
        String code = fixture.currentTotpCode(user);
        fixture.mfaService.verifyForLogin(login.intermediateToken(), code, CONTEXT);

        LoginResult second = fixture.loginService.login(user.login(), PASSWORD, CONTEXT);

        // Still inside the same 30-second step, so the code is cryptographically valid; the
        // counter guard is what refuses it.
        assertThatThrownBy(() -> fixture.mfaService
                .verifyForLogin(second.intermediateToken(), code, CONTEXT))
                .isInstanceOf(MfaException.class);
    }

    @Test
    @DisplayName("an expired challenge token is refused")
    void verifyForLogin_expiredChallenge_refused() {
        enrolAndConfirm();
        LoginResult login = fixture.loginService.login(user.login(), PASSWORD, CONTEXT);

        fixture.clock.advance(fixture.properties.getMfa().getChallengeTtl().plus(Duration.ofMinutes(1)));

        assertThatThrownBy(() -> fixture.mfaService.verifyForLogin(
                login.intermediateToken(), fixture.currentTotpCode(user), CONTEXT))
                .isInstanceOf(MfaException.class)
                .extracting(thrown -> ((MfaException) thrown).getCode())
                .isEqualTo(AuthErrorCodes.MFA_CHALLENGE_INVALID);
    }

    @Test
    @DisplayName("locks verification after too many wrong codes")
    void verifyForLogin_repeatedWrongCodes_locks() {
        enrolAndConfirm();
        LoginResult login = fixture.loginService.login(user.login(), PASSWORD, CONTEXT);
        int max = fixture.properties.getMfa().getMaxFailedAttempts();

        for (int attempt = 0; attempt < max - 1; attempt++) {
            assertThatThrownBy(() -> fixture.mfaService
                    .verifyForLogin(login.intermediateToken(), "000000", CONTEXT))
                    .isInstanceOf(MfaException.class);
        }

        assertThatThrownBy(() -> fixture.mfaService
                .verifyForLogin(login.intermediateToken(), "000000", CONTEXT))
                .isInstanceOf(MfaException.class)
                .extracting(thrown -> ((MfaException) thrown).getCode())
                .isEqualTo(AuthErrorCodes.MFA_LOCKED);
    }

    @Test
    @DisplayName("an administrative reset forces a new enrolment and closes sessions")
    void resetFor_requiresANewEnrolment() {
        enrolAndConfirm();
        AuthTokens session = fixture.sessionService.openSession(user);

        fixture.mfaService.resetFor(user.id(), "admin-1");

        assertThat(fixture.mfaService.statusOf(user)).isEqualTo(MfaStatus.RESET_PENDING);
        assertThat(fixture.sessionService.findSession(session.refreshToken()).orElseThrow()
                .isRevoked()).isTrue();
        assertThat(fixture.events.mfaReset).isEqualTo(1);
        assertThat(fixture.loginService.login(user.login(), PASSWORD, CONTEXT).status())
                .isEqualTo(LoginResult.Status.MFA_ENROLLMENT_REQUIRED);
    }

    @Test
    @DisplayName("step-up refuses a missing code")
    void verifyStepUp_missingCode_refused() {
        enrolAndConfirm();

        assertThatThrownBy(() -> fixture.mfaService.verifyStepUp(user.id(), null))
                .isInstanceOf(MfaException.class)
                .extracting(thrown -> ((MfaException) thrown).getCode())
                .isEqualTo(AuthErrorCodes.MFA_REQUIRED);
    }

    @Test
    @DisplayName("step-up accepts a fresh code")
    void verifyStepUp_validCode_passes() {
        enrolAndConfirm();
        fixture.clock.advance(Duration.ofSeconds(30));

        fixture.mfaService.verifyStepUp(user.id(), fixture.currentTotpCode(user));
    }

    @Test
    @DisplayName("a user with no factor cannot be verified")
    void verifyStepUp_withoutFactor_refused() {
        assertThatThrownBy(() -> fixture.mfaService.verifyStepUp(user.id(), "123456"))
                .isInstanceOf(MfaException.class)
                .extracting(thrown -> ((MfaException) thrown).getCode())
                .isEqualTo(AuthErrorCodes.MFA_NOT_ENROLLED);
    }

    private String enrolmentToken() {
        return fixture.jwtIssuer.issuePurposeToken(
                user.id(), TokenPurpose.MFA_ENROLLMENT,
                fixture.properties.getMfa().getEnrollmentTtl()).token();
    }

    private void enrolAndConfirm() {
        String token = enrolmentToken();
        fixture.mfaService.startEnrollment(token);
        fixture.mfaService.confirmEnrollment(token, fixture.currentTotpCode(user));
    }
}
