package io.github.springauth.core.testsupport;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.LoginFailureReason;
import io.github.springauth.core.model.RequestContext;
import io.github.springauth.core.spi.AuthEventListener;

/** Captures emitted events so tests can assert on the audit seam. */
public class RecordingEventListener implements AuthEventListener {

    public final List<LoginFailureReason> failures = new ArrayList<>();
    public final List<String> successes = new ArrayList<>();
    public int accountLocked;
    public int replayDetected;
    public int mfaEnrolled;
    public int mfaReset;
    public int passwordChanges;

    @Override
    public void onLoginSucceeded(AuthUser user, RequestContext context, Instant at) {
        successes.add(user.id().value());
    }

    @Override
    public void onLoginFailed(AuthUserId userId, String login, LoginFailureReason reason,
                              RequestContext context, Instant at) {
        failures.add(reason);
    }

    @Override
    public void onAccountLocked(AuthUser user, Instant lockedUntil, RequestContext context) {
        accountLocked++;
    }

    @Override
    public void onMfaEnrolled(AuthUser user, Instant at) {
        mfaEnrolled++;
    }

    @Override
    public void onMfaReset(AuthUser user, String performedBy, Instant at) {
        mfaReset++;
    }

    @Override
    public void onPasswordChanged(AuthUser user, boolean selfService, Instant at) {
        passwordChanges++;
    }

    @Override
    public void onRefreshTokenReplayDetected(AuthUserId userId, RequestContext context, Instant at) {
        replayDetected++;
    }
}
