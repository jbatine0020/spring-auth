package io.github.springauth.web.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Request payloads of the bundled endpoints.
 *
 * <p>Grouped in one file because they are small, order-dependent on each other's flow, and only
 * meaningful together. Bean Validation covers presence; every semantic rule lives in the services,
 * so a malformed request fails the same way whether it arrives through these controllers or
 * through an application's own.
 */
public final class AuthRequests {

    private AuthRequests() {
        // container of nested records
    }

    /** Step one: login and password. */
    public record Login(
            @NotBlank(message = "L'identifiant est obligatoire") String login,
            @NotBlank(message = "Le mot de passe est obligatoire") String password) {}

    /** Step two for an enrolled user: the challenge token from step one plus a TOTP code. */
    public record VerifyMfa(
            @NotBlank(message = "Le jeton de session est obligatoire") String challengeToken,
            @NotBlank(message = "Le code est obligatoire") String code) {}

    /** Step two for a user who still has to enrol: starts the enrolment. */
    public record StartEnrollment(
            @NotBlank(message = "Le jeton de session est obligatoire") String enrollmentToken) {}

    /** Confirms an enrolment with the first code produced by the authenticator. */
    public record ConfirmEnrollment(
            @NotBlank(message = "Le jeton de session est obligatoire") String enrollmentToken,
            @NotBlank(message = "Le code est obligatoire") String code) {}

    /**
     * Exchanges a refresh token. The field is optional in the body when the deployment serves the
     * refresh token as a cookie.
     */
    public record Refresh(String refreshToken) {}

    /** Closes one session. */
    public record Logout(String refreshToken) {}

    /** Starts a forgotten-password flow. */
    public record RequestPasswordReset(
            @NotBlank(message = "L'identifiant est obligatoire") String login) {}

    /** Completes a forgotten-password flow. {@code otp} is unused in link-only deployments. */
    public record ConfirmPasswordReset(
            @NotBlank(message = "Le jeton est obligatoire") String token,
            String otp,
            @NotBlank(message = "Le nouveau mot de passe est obligatoire") String newPassword) {}

    /** Self-service password change. */
    public record RequiredPasswordChange(
            @NotBlank(message = "Le nouveau mot de passe est obligatoire") String newPassword) {}

    public record ChangePassword(
            @NotBlank(message = "Le mot de passe actuel est obligatoire") String currentPassword,
            @NotBlank(message = "Le nouveau mot de passe est obligatoire") String newPassword) {}

    /** Administrative password set. */
    public record SetPassword(
            @NotBlank(message = "Le nouveau mot de passe est obligatoire") String newPassword,
            boolean mustChangeAtNextLogin) {}

    /** Redeems an invitation and sets the first password. */
    public record RedeemInvitation(
            @NotBlank(message = "Le jeton d'invitation est obligatoire") String token,
            @NotBlank(message = "Le mot de passe est obligatoire") String password) {}
}
