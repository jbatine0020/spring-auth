package io.github.springauth.core.error;

/**
 * Service-to-service authentication failed: bad signature, unknown peer, expired token,
 * or a replayed {@code jti}.
 *
 * <p>The reason is logged server-side and never returned to the peer.
 */
public class InternalAuthException extends AuthException {

    private final String reason;

    public InternalAuthException(String reason) {
        super(AuthErrorCodes.INTERNAL_AUTH_FAILED, "Authentification inter-services refusée");
        this.reason = reason;
    }

    /** Technical detail for the server log. Never expose it in a response body. */
    public String getReason() {
        return reason;
    }
}
