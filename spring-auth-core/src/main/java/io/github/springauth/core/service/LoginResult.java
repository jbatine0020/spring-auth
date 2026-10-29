package io.github.springauth.core.service;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.MfaStatus;

/**
 * Outcome of the password step.
 *
 * <p>A correct password does not always end the flow: when a second factor applies, the caller
 * gets a short-lived token and must come back through the MFA endpoints. The {@link Status} tells
 * the client which of the three shapes it received.
 *
 * @param status             what the client must do next
 * @param userId             authenticated subject
 * @param login              login that was used, echoed for the client
 * @param mfaStatus          enrolment state of the second factor
 * @param mustChangePassword the password is expired or an administrator forced a change
 * @param intermediateToken  challenge or enrolment token, null when authentication is complete
 * @param tokens             access and refresh tokens, null unless status is {@link Status#AUTHENTICATED}
 */
public record LoginResult(
        Status status,
        AuthUserId userId,
        String login,
        MfaStatus mfaStatus,
        boolean mustChangePassword,
        String intermediateToken,
        AuthTokens tokens) {

    public enum Status {

        /** Nothing left to do: tokens are in the response. */
        AUTHENTICATED,

        /** Submit a TOTP code with the challenge token to finish authenticating. */
        MFA_CHALLENGE_REQUIRED,

        /** Enrol an authenticator with the enrolment token, then confirm it with a first code. */
        MFA_ENROLLMENT_REQUIRED
    }

    public static LoginResult authenticated(AuthUserId userId, String login, MfaStatus mfaStatus,
                                            boolean mustChangePassword, AuthTokens tokens) {
        return new LoginResult(Status.AUTHENTICATED, userId, login, mfaStatus,
                mustChangePassword, null, tokens);
    }

    public static LoginResult mfaChallengeRequired(AuthUserId userId, String login,
                                                   boolean mustChangePassword, String challengeToken) {
        return new LoginResult(Status.MFA_CHALLENGE_REQUIRED, userId, login, MfaStatus.CONFIGURED,
                mustChangePassword, challengeToken, null);
    }

    public static LoginResult mfaEnrollmentRequired(AuthUserId userId, String login, MfaStatus mfaStatus,
                                                    boolean mustChangePassword, String enrollmentToken) {
        return new LoginResult(Status.MFA_ENROLLMENT_REQUIRED, userId, login, mfaStatus,
                mustChangePassword, enrollmentToken, null);
    }
}
