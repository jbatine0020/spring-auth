package io.github.springauth.web.controller;

import java.time.Duration;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.service.AuthTokens;
import io.github.springauth.core.service.InvitationService;
import io.github.springauth.core.service.LoginHistoryService;
import io.github.springauth.core.service.LoginResult;
import io.github.springauth.core.service.LoginService;
import io.github.springauth.core.service.MfaService;
import io.github.springauth.core.service.PasswordService;
import io.github.springauth.core.service.SessionService;
import io.github.springauth.core.service.TotpEnrollment;
import io.github.springauth.web.dto.AuthRequests;
import io.github.springauth.web.dto.AuthResponses;
import io.github.springauth.web.support.CurrentUser;
import io.github.springauth.web.support.RefreshTokenCookies;
import io.github.springauth.web.support.RequestContexts;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.responses.ApiResponse;

/**
 * The authentication API.
 *
 * <p>Registered only when {@code spring-auth.web.enabled} is true (the default). Applications that
 * need a different contract turn it off and call the services from their own controllers; the
 * services are the real API, these endpoints are a convenience.
 *
 * <p>Endpoints under this controller are unauthenticated by design, because they are how a caller
 * becomes authenticated in the first place. Each one carries its own credential in the body: a
 * password, a challenge token, a refresh token, a reset link. Rate limiting, not authentication,
 * is what protects them.
 *
 * <table>
 *   <caption>Endpoints</caption>
 *   <tr><th>Method and path</th><th>Purpose</th></tr>
 *   <tr><td>POST /login</td><td>Password step</td></tr>
 *   <tr><td>POST /mfa/verify</td><td>TOTP step for an enrolled user</td></tr>
 *   <tr><td>POST /mfa/enrollment/start</td><td>Generates a factor</td></tr>
 *   <tr><td>POST /mfa/enrollment/confirm</td><td>Confirms it and opens a session</td></tr>
 *   <tr><td>POST /refresh</td><td>Rotates the refresh token</td></tr>
 *   <tr><td>POST /logout</td><td>Closes the session</td></tr>
 *   <tr><td>POST /password-reset:request</td><td>Starts a forgotten-password flow</td></tr>
 *   <tr><td>POST /password-reset:confirm</td><td>Completes it</td></tr>
 *   <tr><td>POST /password:change</td><td>Self-service change (authenticated)</td></tr>
 *   <tr><td>GET /me/login-history</td><td>Recent attempts (authenticated)</td></tr>
 *   <tr><td>POST /invitations:verify</td><td>Pre-validates an invitation link</td></tr>
 *   <tr><td>POST /invitations:redeem</td><td>Redeems it and sets the first password</td></tr>
 * </table>
 */
@RestController
@RequestMapping("${spring-auth.web.base-path:/api/v1/auth}")
@Tag(name = "Local authentication", description = "Password, MFA, session and password recovery operations")
public class AuthController {

    private static final int DEFAULT_HISTORY_LIMIT = 20;
    private static final Duration FAILURE_WINDOW = Duration.ofDays(7);

    private final LoginService loginService;
    private final MfaService mfaService;
    private final SessionService sessionService;
    private final PasswordService passwordService;
    private final InvitationService invitationService;
    private final LoginHistoryService loginHistoryService;
    private final RefreshTokenCookies refreshCookies;
    private final AuthProperties properties;

    public AuthController(LoginService loginService,
                          MfaService mfaService,
                          SessionService sessionService,
                          PasswordService passwordService,
                          InvitationService invitationService,
                          LoginHistoryService loginHistoryService,
                          RefreshTokenCookies refreshCookies,
                          AuthProperties properties) {
        this.loginService = loginService;
        this.mfaService = mfaService;
        this.sessionService = sessionService;
        this.passwordService = passwordService;
        this.invitationService = invitationService;
        this.loginHistoryService = loginHistoryService;
        this.refreshCookies = refreshCookies;
        this.properties = properties;
    }

    /**
     * Password step. Returns tokens, or a short-lived token pointing at the MFA step. Read
     * {@code status} to tell which.
     */
    @PostMapping("/login")
    @Operation(summary = "Authenticate a local user", description = "Authenticates a user managed by spring-auth. Use the returned intermediateToken when MFA is required.", responses = {
            @ApiResponse(responseCode = "200", description = "Credentials accepted or MFA challenge returned"),
            @ApiResponse(responseCode = "401", description = "Credentials are invalid")
    })
    public ResponseEntity<AuthResponses.LoginResponse> login(@Valid @RequestBody AuthRequests.Login request,
                                                             HttpServletRequest httpRequest,
                                                             HttpServletResponse httpResponse) {
        LoginResult result = loginService.login(
                request.login(), request.password(), RequestContexts.from(httpRequest));
        AuthResponses.LoginResponse body = AuthResponses.LoginResponse.from(result);
        if (result.tokens() != null) {
            refreshCookies.write(httpResponse, result.tokens().refreshToken());
            if (refreshCookies.isEnabled()) {
                body = new AuthResponses.LoginResponse(body.status(), body.userId(), body.login(),
                        body.mfaStatus(), body.mustChangePassword(), body.intermediateToken(),
                        body.tokens().withoutRefreshToken());
            }
        }
        return ResponseEntity.ok(body);
    }

    /** TOTP step for a user who already owns a confirmed factor. */
    @PostMapping("/mfa/verify")
    @Operation(summary = "Verify a login MFA challenge", description = "Consumes the short-lived challenge token and a six-digit TOTP code.")
    public ResponseEntity<AuthResponses.Tokens> verifyMfa(@Valid @RequestBody AuthRequests.VerifyMfa request,
                                                          HttpServletRequest httpRequest,
                                                          HttpServletResponse httpResponse) {
        AuthTokens tokens = mfaService.verifyForLogin(
                request.challengeToken(), request.code(), RequestContexts.from(httpRequest));
        return respondWithTokens(tokens, httpResponse);
    }

    /**
     * Generates a factor for a user holding an enrolment token.
     *
     * <p>The secret is in the response: this is the only moment it exists in clear.
     */
    @PostMapping("/mfa/enrollment/start")
    public ResponseEntity<AuthResponses.EnrollmentResponse> startEnrollment(
            @Valid @RequestBody AuthRequests.StartEnrollment request) {
        TotpEnrollment enrollment = mfaService.startEnrollment(request.enrollmentToken());
        return ResponseEntity.ok(AuthResponses.EnrollmentResponse.from(enrollment));
    }

    /** Confirms the enrolment with a first valid code and opens a session. */
    @PostMapping("/mfa/enrollment/confirm")
    public ResponseEntity<AuthResponses.Tokens> confirmEnrollment(
            @Valid @RequestBody AuthRequests.ConfirmEnrollment request,
            HttpServletResponse httpResponse) {
        AuthTokens tokens = mfaService.confirmEnrollment(request.enrollmentToken(), request.code());
        return respondWithTokens(tokens, httpResponse);
    }

    /** Rotates the refresh token and returns a new pair. */
    @PostMapping("/refresh")
    @Operation(summary = "Refresh session tokens", description = "Rotates a refresh token. Send the refreshToken in the JSON body unless refresh-token cookies are enabled.")
    public ResponseEntity<AuthResponses.Tokens> refresh(@RequestBody(required = false) AuthRequests.Refresh request,
                                                        HttpServletRequest httpRequest,
                                                        HttpServletResponse httpResponse) {
        String presented = refreshCookies.resolve(httpRequest,
                request == null ? null : request.refreshToken());
        AuthTokens tokens = sessionService.refresh(presented, RequestContexts.from(httpRequest));
        return respondWithTokens(tokens, httpResponse);
    }

    /** Closes the session. Idempotent: an unknown token is not an error. */
    @PostMapping("/logout")
    @Operation(summary = "Close the current session", description = "Revokes the presented refresh token. The operation is idempotent.")
    public ResponseEntity<AuthResponses.Acknowledgement> logout(
            @RequestBody(required = false) AuthRequests.Logout request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        sessionService.logout(refreshCookies.resolve(httpRequest,
                request == null ? null : request.refreshToken()));
        refreshCookies.clear(httpResponse);
        return ResponseEntity.ok(AuthResponses.Acknowledgement.ok("Session fermée"));
    }

    /**
     * Starts a forgotten-password flow.
     *
     * <p>Always answers 202 with the same message, registered address or not: a differentiated
     * answer would tell an anonymous caller which addresses exist.
     */
    @PostMapping("/password-reset:request")
    public ResponseEntity<AuthResponses.Acknowledgement> requestPasswordReset(
            @Valid @RequestBody AuthRequests.RequestPasswordReset request,
            HttpServletRequest httpRequest) {
        passwordService.requestReset(request.login(), RequestContexts.from(httpRequest));
        return ResponseEntity.accepted().body(AuthResponses.Acknowledgement.ok(
                "Si un compte correspond à cet identifiant, les instructions viennent d'être envoyées"));
    }

    /** Completes a forgotten-password flow. */
    @PostMapping("/password-reset:confirm")
    public ResponseEntity<AuthResponses.Acknowledgement> confirmPasswordReset(
            @Valid @RequestBody AuthRequests.ConfirmPasswordReset request) {
        passwordService.confirmReset(request.token(), request.otp(), request.newPassword());
        return ResponseEntity.ok(AuthResponses.Acknowledgement.ok("Mot de passe réinitialisé"));
    }

    /**
     * Self-service password change. Closes every session, so the client must authenticate again
     * with the new password.
     */
    @PostMapping("/password:change")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<AuthResponses.Acknowledgement> changePassword(
            @Valid @RequestBody AuthRequests.ChangePassword request,
            HttpServletResponse httpResponse) {
        // The subject comes from the validated token, never from the request.
        passwordService.changeOwnPassword(
                CurrentUser.requireId(), request.currentPassword(), request.newPassword());
        refreshCookies.clear(httpResponse);
        return ResponseEntity.ok(AuthResponses.Acknowledgement.ok(
                "Mot de passe modifié, veuillez vous reconnecter"));
    }

    /** A required change uses the authenticated session, without asking for the temporary secret again. */
    @PostMapping("/password:first-change")
    @PreAuthorize("isAuthenticated() and principal.claims['must_change_password'] == true")
    public ResponseEntity<AuthResponses.Acknowledgement> completeRequiredPasswordChange(
            @Valid @RequestBody AuthRequests.RequiredPasswordChange request,
            HttpServletResponse httpResponse) {
        passwordService.completeRequiredPasswordChange(CurrentUser.requireId(), request.newPassword());
        refreshCookies.clear(httpResponse);
        return ResponseEntity.ok(AuthResponses.Acknowledgement.ok(
                "Mot de passe modifié, veuillez vous reconnecter"));
    }

    /** Recent authentication attempts of the caller. */
    @GetMapping("/me/login-history")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<AuthResponses.LoginAttemptResponse>> loginHistory(
            @RequestParam(name = "limit", defaultValue = "" + DEFAULT_HISTORY_LIMIT) int limit) {
        AuthUserId userId = CurrentUser.requireId();
        return ResponseEntity.ok(loginHistoryService.recentFor(userId, limit).stream()
                .map(AuthResponses.LoginAttemptResponse::from)
                .toList());
    }

    /** Number of failed attempts on the caller's account over the last week. */
    @GetMapping("/me/failed-attempts")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Long> recentFailures() {
        return ResponseEntity.ok(
                loginHistoryService.countRecentFailures(CurrentUser.requireId(), FAILURE_WINDOW));
    }

    /**
     * Pre-validates an invitation link so the activation page can render before the user types
     * anything. Consumes nothing.
     */
    @PostMapping("/invitations:verify")
    public ResponseEntity<AuthResponses.Acknowledgement> verifyInvitation(
            @RequestBody AuthRequests.RedeemInvitation request) {
        AuthUser user = invitationService.verify(request.token());
        return ResponseEntity.ok(AuthResponses.Acknowledgement.ok(user.login()));
    }

    /** Redeems the invitation and sets the first password. */
    @PostMapping("/invitations:redeem")
    public ResponseEntity<AuthResponses.Acknowledgement> redeemInvitation(
            @Valid @RequestBody AuthRequests.RedeemInvitation request) {
        invitationService.redeem(request.token(), request.password());
        return ResponseEntity.ok(AuthResponses.Acknowledgement.ok(
                "Compte activé, vous pouvez maintenant vous connecter"));
    }

    /** Password rules, for a client that wants to show them next to the field. */
    @GetMapping("/password-policy")
    public ResponseEntity<AuthResponses.Acknowledgement> passwordPolicy() {
        return ResponseEntity.ok(AuthResponses.Acknowledgement.ok(passwordService.describePolicy()));
    }

    private ResponseEntity<AuthResponses.Tokens> respondWithTokens(AuthTokens tokens,
                                                                   HttpServletResponse httpResponse) {
        refreshCookies.write(httpResponse, tokens.refreshToken());
        AuthResponses.Tokens body = AuthResponses.Tokens.from(tokens);
        return ResponseEntity.ok(refreshCookies.isEnabled() ? body.withoutRefreshToken() : body);
    }

    /** Exposed for tests and diagnostics. */
    AuthProperties getProperties() {
        return properties;
    }
}
