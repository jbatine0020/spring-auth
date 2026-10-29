package io.github.springauth.web.controller;

import java.util.List;

import jakarta.validation.Valid;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.service.InvitationService;
import io.github.springauth.core.service.LoginHistoryService;
import io.github.springauth.core.service.MfaService;
import io.github.springauth.core.service.PasswordService;
import io.github.springauth.core.service.SessionService;
import io.github.springauth.web.dto.AuthRequests;
import io.github.springauth.web.dto.AuthResponses;
import io.github.springauth.web.support.CurrentUser;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Operator actions on someone else's account.
 *
 * <p>Every endpoint is gated by a permission from {@link AuthPermissions}, which no role carries
 * until the application grants it. All of them close the target's sessions where it matters: a
 * password reset or an MFA reset that left the compromised session alive would miss the point.
 */
@RestController
@RequestMapping("${spring-auth.web.base-path:/api/v1/auth}/admin")
@SecurityRequirement(name = "bearerAuth")
public class AuthAdminController {

    private static final int DEFAULT_HISTORY_LIMIT = 50;

    private final PasswordService passwordService;
    private final MfaService mfaService;
    private final SessionService sessionService;
    private final InvitationService invitationService;
    private final LoginHistoryService loginHistoryService;

    public AuthAdminController(PasswordService passwordService,
                               MfaService mfaService,
                               SessionService sessionService,
                               InvitationService invitationService,
                               LoginHistoryService loginHistoryService) {
        this.passwordService = passwordService;
        this.mfaService = mfaService;
        this.sessionService = sessionService;
        this.invitationService = invitationService;
        this.loginHistoryService = loginHistoryService;
    }

    /** Sets a user's password, optionally forcing a change at their next login. */
    @PostMapping("/users/{userId}/password:set")
    @PreAuthorize("hasAuthority('" + AuthPermissions.USERS_PASSWORD + "')")
    public ResponseEntity<AuthResponses.Acknowledgement> setPassword(
            @PathVariable String userId,
            @Valid @RequestBody AuthRequests.SetPassword request) {
        passwordService.setPassword(AuthUserId.of(userId), request.newPassword(),
                request.mustChangeAtNextLogin());
        return ResponseEntity.ok(AuthResponses.Acknowledgement.ok("Mot de passe défini"));
    }

    /** Unlocks an account locked by repeated failures, ahead of its natural expiry. */
    @PostMapping("/users/{userId}:unlock")
    @PreAuthorize("hasAuthority('" + AuthPermissions.USERS_PASSWORD + "')")
    public ResponseEntity<AuthResponses.Acknowledgement> unlock(@PathVariable String userId) {
        passwordService.unlock(AuthUserId.of(userId));
        return ResponseEntity.ok(AuthResponses.Acknowledgement.ok("Compte déverrouillé"));
    }

    /** Wipes a user's second factor; they must enrol again at their next login. */
    @PostMapping("/users/{userId}/mfa:reset")
    @PreAuthorize("hasAuthority('" + AuthPermissions.USERS_MFA + "')")
    @Transactional
    public ResponseEntity<AuthResponses.Acknowledgement> resetMfa(@PathVariable String userId) {
        String performedBy = CurrentUser.id().map(AuthUserId::value).orElse("system");
        mfaService.resetFor(AuthUserId.of(userId), performedBy);
        return ResponseEntity.ok(AuthResponses.Acknowledgement.ok("Facteur MFA réinitialisé"));
    }

    /** Closes every session of a user. */
    @PostMapping("/users/{userId}/sessions:revoke")
    @PreAuthorize("hasAuthority('" + AuthPermissions.USERS_SESSIONS + "')")
    public ResponseEntity<AuthResponses.Acknowledgement> revokeSessions(@PathVariable String userId) {
        int revoked = sessionService.revokeAllSessions(AuthUserId.of(userId));
        return ResponseEntity.ok(AuthResponses.Acknowledgement.ok(revoked + " session(s) fermée(s)"));
    }

    /**
     * Issues an invitation link and hands it to the configured messenger.
     *
     * <p>The raw token is not returned: it goes to the user, not to the operator.
     */
    @PostMapping("/users/{userId}/invitations")
    @PreAuthorize("hasAuthority('" + AuthPermissions.USERS_INVITE + "')")
    public ResponseEntity<AuthResponses.Acknowledgement> invite(@PathVariable String userId) {
        invitationService.invite(AuthUserId.of(userId));
        return ResponseEntity.ok(AuthResponses.Acknowledgement.ok("Invitation envoyée"));
    }

    /** Revokes every pending invitation of a user. */
    @PostMapping("/users/{userId}/invitations:revoke")
    @PreAuthorize("hasAuthority('" + AuthPermissions.USERS_INVITE + "')")
    public ResponseEntity<AuthResponses.Acknowledgement> revokeInvitations(@PathVariable String userId) {
        invitationService.revokeFor(AuthUserId.of(userId));
        return ResponseEntity.ok(AuthResponses.Acknowledgement.ok("Invitations révoquées"));
    }

    /** Authentication history of a user, for a support or fraud investigation. */
    @GetMapping("/users/{userId}/login-history")
    @PreAuthorize("hasAuthority('" + AuthPermissions.USERS_SESSIONS + "')")
    public ResponseEntity<List<AuthResponses.LoginAttemptResponse>> loginHistory(
            @PathVariable String userId,
            @RequestParam(name = "limit", defaultValue = "" + DEFAULT_HISTORY_LIMIT) int limit) {
        return ResponseEntity.ok(loginHistoryService.recentFor(AuthUserId.of(userId), limit).stream()
                .map(AuthResponses.LoginAttemptResponse::from)
                .toList());
    }
}
