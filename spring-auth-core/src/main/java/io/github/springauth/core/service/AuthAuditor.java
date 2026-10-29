package io.github.springauth.core.service;

import java.time.Instant;
import java.util.List;
import java.util.function.Consumer;

import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.LoginAttempt;
import io.github.springauth.core.model.LoginFailureReason;
import io.github.springauth.core.model.RequestContext;
import io.github.springauth.core.port.LoginHistoryStore;
import io.github.springauth.core.spi.AuthEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fans authentication events out to the login history and to every registered listener, and
 * swallows their failures.
 *
 * <p>The swallowing is deliberate. Recording an attempt is valuable but subordinate: if the audit
 * table is unreachable or a listener throws, the right behaviour is a logged warning, not a
 * failed login for every user of the platform. The one thing that must never be lost is the
 * failure <i>counter</i> on the credentials themselves, and that lives in the main transaction.
 */
public class AuthAuditor {

    private static final Logger log = LoggerFactory.getLogger(AuthAuditor.class);

    private final LoginHistoryStore loginHistoryStore;
    private final List<AuthEventListener> listeners;

    public AuthAuditor(LoginHistoryStore loginHistoryStore, List<AuthEventListener> listeners) {
        this.loginHistoryStore = loginHistoryStore;
        this.listeners = listeners == null ? List.of() : List.copyOf(listeners);
    }

    public void loginSucceeded(AuthUser user, RequestContext context, Instant at) {
        record(() -> loginHistoryStore.append(LoginAttempt.success(user.id(), user.login(), context, at)));
        notifyAll(listener -> listener.onLoginSucceeded(user, context, at));
    }

    /** @param userId null when no account matched the submitted login */
    public void loginFailed(AuthUserId userId, String login, LoginFailureReason reason,
                            RequestContext context, Instant at) {
        record(() -> loginHistoryStore.append(LoginAttempt.failure(userId, login, reason, context, at)));
        notifyAll(listener -> listener.onLoginFailed(userId, login, reason, context, at));
    }

    public void accountLocked(AuthUser user, Instant lockedUntil, RequestContext context) {
        notifyAll(listener -> listener.onAccountLocked(user, lockedUntil, context));
    }

    public void mfaEnrolled(AuthUser user, Instant at) {
        notifyAll(listener -> listener.onMfaEnrolled(user, at));
    }

    public void mfaVerificationFailed(AuthUser user, RequestContext context, Instant at) {
        record(() -> loginHistoryStore.append(LoginAttempt.failure(
                user.id(), user.login(), LoginFailureReason.BAD_MFA_CODE, context, at)));
        notifyAll(listener -> listener.onMfaVerificationFailed(user, context, at));
    }

    public void mfaReset(AuthUser user, String performedBy, Instant at) {
        notifyAll(listener -> listener.onMfaReset(user, performedBy, at));
    }

    public void passwordChanged(AuthUser user, boolean selfService, Instant at) {
        notifyAll(listener -> listener.onPasswordChanged(user, selfService, at));
    }

    public void passwordResetRequested(AuthUser user, RequestContext context, Instant at) {
        notifyAll(listener -> listener.onPasswordResetRequested(user, context, at));
    }

    public void refreshTokenReplayDetected(AuthUserId userId, RequestContext context, Instant at) {
        notifyAll(listener -> listener.onRefreshTokenReplayDetected(userId, context, at));
    }

    public void logout(AuthUserId userId, Instant at) {
        notifyAll(listener -> listener.onLogout(userId, at));
    }

    public void invitationRedeemed(AuthUser user, Instant at) {
        notifyAll(listener -> listener.onInvitationRedeemed(user, at));
    }

    private void record(Runnable action) {
        try {
            action.run();
        } catch (RuntimeException ex) {
            log.warn("spring-auth: login history could not be written", ex);
        }
    }

    private void notifyAll(Consumer<AuthEventListener> action) {
        for (AuthEventListener listener : listeners) {
            try {
                action.accept(listener);
            } catch (RuntimeException ex) {
                log.warn("spring-auth: auth event listener {} failed",
                        listener.getClass().getSimpleName(), ex);
            }
        }
    }
}
