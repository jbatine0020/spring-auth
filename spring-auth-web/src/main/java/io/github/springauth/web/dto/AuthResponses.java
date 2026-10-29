package io.github.springauth.web.dto;

import java.time.Instant;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.github.springauth.core.model.LoginAttempt;
import io.github.springauth.core.model.Role;
import io.github.springauth.core.service.AuthTokens;
import io.github.springauth.core.service.LoginResult;
import io.github.springauth.core.service.TotpEnrollment;

/**
 * Response payloads of the bundled endpoints.
 *
 * <p>Null fields are omitted, so a client reading a login response sees either
 * {@code intermediateToken} or {@code tokens}, never both keys with one of them null.
 */
public final class AuthResponses {

    private AuthResponses() {
        // container of nested records
    }

    /** Outcome of the password step. See {@link LoginResult.Status}. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record LoginResponse(
            String status,
            String userId,
            String login,
            String mfaStatus,
            boolean mustChangePassword,
            String intermediateToken,
            Tokens tokens) {

        public static LoginResponse from(LoginResult result) {
            return new LoginResponse(
                    result.status().name(),
                    result.userId().value(),
                    result.login(),
                    result.mfaStatus().name(),
                    result.mustChangePassword(),
                    result.intermediateToken(),
                    result.tokens() == null ? null : Tokens.from(result.tokens()));
        }
    }

    /**
     * Access and refresh tokens.
     *
     * <p>{@code refreshToken} is null when the deployment serves it as an HttpOnly cookie: the
     * point of that mode is that JavaScript never sees the value.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Tokens(
            String accessToken,
            String refreshToken,
            String tokenType,
            long expiresIn,
            Instant expiresAt) {

        public static Tokens from(AuthTokens tokens) {
            return new Tokens(tokens.accessToken(), tokens.refreshToken(), tokens.tokenType(),
                    tokens.expiresInSeconds(), tokens.expiresAt());
        }

        /** Same payload with the refresh token withheld, for the cookie-based mode. */
        public Tokens withoutRefreshToken() {
            return new Tokens(accessToken, null, tokenType, expiresIn, expiresAt);
        }
    }

    /** Enrolment material: render {@code otpauthUri} as a QR code. */
    public record EnrollmentResponse(String secret, String otpauthUri, String issuer, String account) {

        public static EnrollmentResponse from(TotpEnrollment enrollment) {
            return new EnrollmentResponse(enrollment.base32Secret(), enrollment.otpauthUri(),
                    enrollment.issuer(), enrollment.account());
        }
    }

    /** One entry of the authentication history. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record LoginAttemptResponse(
            boolean successful,
            String failureReason,
            String ipAddress,
            String userAgent,
            Instant occurredAt) {

        public static LoginAttemptResponse from(LoginAttempt attempt) {
            return new LoginAttemptResponse(
                    attempt.isSuccessful(),
                    attempt.getFailureReason() == null ? null : attempt.getFailureReason().name(),
                    attempt.getIpAddress(),
                    attempt.getUserAgent(),
                    attempt.getOccurredAt());
        }
    }

    /** A role and its permissions. */
    public record RoleResponse(
            String code,
            String name,
            String description,
            List<String> permissions,
            String status,
            boolean system) {

        public static RoleResponse from(Role role) {
            return new RoleResponse(role.getCode(), role.getName(), role.getDescription(),
                    role.getPermissions().stream().sorted().toList(),
                    role.getStatus().name(), role.isSystem());
        }
    }

    public record RolePageResponse(int page, int size, int pages, long count, long countAll,
                                   List<RoleResponse> list) {
        public static RolePageResponse from(io.github.springauth.core.service.RoleService.RolePage page) {
            return new RolePageResponse(page.page(), page.size(), page.pages(), page.list().size(),
                    page.countAll(), page.list().stream().map(RoleResponse::from).toList());
        }
    }

    /** Acknowledgement for endpoints that deliberately return nothing meaningful. */
    public record Acknowledgement(String message) {

        public static Acknowledgement ok(String message) {
            return new Acknowledgement(message);
        }
    }
}
