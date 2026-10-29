package io.github.springauth.core.error;

import java.util.Objects;

/**
 * Base class of every error raised by spring-auth.
 *
 * <p>Each exception carries a stable {@link #getCode() code}, the contract clients and tests
 * rely on, next to a default human-readable message. Codes never change across versions;
 * messages may. Applications that need a different wording (or another language) map the code
 * themselves in their exception handler rather than parsing the message.
 *
 * @see AuthErrorCodes for the exhaustive list
 */
public abstract class AuthException extends RuntimeException {

    private final String code;

    protected AuthException(String code, String message) {
        super(message);
        this.code = Objects.requireNonNull(code, "code is required");
    }

    protected AuthException(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = Objects.requireNonNull(code, "code is required");
    }

    /** Stable, machine-readable error code. */
    public String getCode() {
        return code;
    }
}
