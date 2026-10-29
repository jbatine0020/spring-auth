package io.github.springauth.core.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * One recorded authentication attempt, successful or not.
 *
 * <p>This is the only place where the real reason behind a generic {@code LOGIN_INVALID} is kept.
 * It feeds security dashboards ("five failures then a success from a new address") and answers the
 * audit question of who tried to reach an account and when.
 *
 * <p>{@code userId} is null when the submitted login matched no account: there is nothing to
 * attach the attempt to, but the attempt itself is still worth keeping.
 */
public final class LoginAttempt {

    private final UUID id;
    private final AuthUserId userId;
    private final String login;
    private final boolean successful;
    private final LoginFailureReason failureReason;
    private final String ipAddress;
    private final String userAgent;
    private final Instant occurredAt;

    private LoginAttempt(UUID id, AuthUserId userId, String login, boolean successful,
                         LoginFailureReason failureReason, String ipAddress, String userAgent,
                         Instant occurredAt) {
        this.id = Objects.requireNonNull(id, "id is required");
        this.userId = userId;
        this.login = login;
        this.successful = successful;
        this.failureReason = failureReason;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.occurredAt = Objects.requireNonNull(occurredAt, "occurredAt is required");
    }

    public static LoginAttempt success(AuthUserId userId, String login, RequestContext context,
                                       Instant occurredAt) {
        return new LoginAttempt(UUID.randomUUID(), Objects.requireNonNull(userId, "userId is required"),
                login, true, null, context.ipAddress(), context.userAgent(), occurredAt);
    }

    public static LoginAttempt failure(AuthUserId userId, String login, LoginFailureReason reason,
                                       RequestContext context, Instant occurredAt) {
        return new LoginAttempt(UUID.randomUUID(), userId, login, false,
                Objects.requireNonNull(reason, "reason is required"),
                context.ipAddress(), context.userAgent(), occurredAt);
    }

    /** Rebuilds an instance from storage. Used by persistence adapters only. */
    public static LoginAttempt restore(UUID id, AuthUserId userId, String login, boolean successful,
                                       LoginFailureReason failureReason, String ipAddress,
                                       String userAgent, Instant occurredAt) {
        return new LoginAttempt(id, userId, login, successful, failureReason, ipAddress,
                userAgent, occurredAt);
    }

    public UUID getId() {
        return id;
    }

    public AuthUserId getUserId() {
        return userId;
    }

    public String getLogin() {
        return login;
    }

    public boolean isSuccessful() {
        return successful;
    }

    public LoginFailureReason getFailureReason() {
        return failureReason;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }
}
