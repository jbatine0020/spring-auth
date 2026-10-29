package io.github.springauth.core.identity;

/** Safe classification of an identity provider failure. */
public class IdentityProviderException extends Exception {

    public enum Kind {
        INVALID_CREDENTIALS,
        PROVIDER_UNAVAILABLE,
        INVALID_RESPONSE
    }

    private final Kind kind;

    public IdentityProviderException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public IdentityProviderException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }
}
