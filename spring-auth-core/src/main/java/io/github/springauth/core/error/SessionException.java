package io.github.springauth.core.error;

/**
 * Refresh-token and session failures.
 *
 * <p>{@link #replayDetected()} is the security-relevant one: presenting an already-rotated
 * refresh token means the secret leaked, so the whole family is invalidated by the caller.
 */
public class SessionException extends AuthException {

    private SessionException(String code, String message) {
        super(code, message);
    }

    /** Token unknown, expired, or revoked through a logout. */
    public static SessionException invalidRefreshToken() {
        return new SessionException(AuthErrorCodes.REFRESH_TOKEN_INVALID,
                "Session expirée, veuillez vous reconnecter");
    }

    /** A revoked token was presented again. Treated as theft. */
    public static SessionException replayDetected() {
        return new SessionException(AuthErrorCodes.REFRESH_TOKEN_REPLAY,
                "Session compromise détectée, toutes les sessions ont été fermées");
    }

    /** The access token predates a revocation stamp for this user. */
    public static SessionException revoked() {
        return new SessionException(AuthErrorCodes.SESSION_REVOKED,
                "Session expirée, veuillez vous reconnecter");
    }
}
