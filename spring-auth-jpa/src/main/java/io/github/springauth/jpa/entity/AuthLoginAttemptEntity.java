package io.github.springauth.jpa.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.LoginAttempt;
import io.github.springauth.core.model.LoginFailureReason;

/**
 * Row of {@code auth_login_attempts}.
 *
 * <p>The fastest-growing table of the schema: every attempt, successful or not, lands here. Prune
 * it on a retention schedule through {@code LoginHistoryService.purgeOlderThan}.
 *
 * <p>{@code user_id} is nullable because an attempt against an unknown login has no account to
 * attach to, yet is exactly the kind of attempt worth keeping.
 */
@Entity
@Table(name = "auth_login_attempts")
public class AuthLoginAttemptEntity {

    @Id
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "user_id", length = 64)
    private String userId;

    @Column(name = "login", length = 320)
    private String login;

    @Column(name = "success_flag", nullable = false)
    private boolean successful;

    @Enumerated(EnumType.STRING)
    @Column(name = "failure_reason", length = 40)
    private LoginFailureReason failureReason;

    @Column(name = "ip_address", length = 64)
    private String ipAddress;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    protected AuthLoginAttemptEntity() {
        // required by JPA
    }

    public static AuthLoginAttemptEntity fromDomain(LoginAttempt attempt) {
        AuthLoginAttemptEntity entity = new AuthLoginAttemptEntity();
        entity.id = attempt.getId();
        entity.userId = attempt.getUserId() == null ? null : attempt.getUserId().value();
        entity.login = truncate(attempt.getLogin(), 320);
        entity.successful = attempt.isSuccessful();
        entity.failureReason = attempt.getFailureReason();
        entity.ipAddress = truncate(attempt.getIpAddress(), 64);
        entity.userAgent = truncate(attempt.getUserAgent(), 512);
        entity.occurredAt = attempt.getOccurredAt();
        return entity;
    }

    public LoginAttempt toDomain() {
        return LoginAttempt.restore(id, userId == null ? null : AuthUserId.of(userId), login,
                successful, failureReason, ipAddress, userAgent, occurredAt);
    }

    /**
     * Client-supplied values land here verbatim; a hostile user agent is easily longer than the
     * column, and an insert failure would break the login it is meant to record.
     */
    private static String truncate(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        return value.length() <= maxLength ? value : value.substring(0, maxLength);
    }

    public UUID getId() {
        return id;
    }
}
