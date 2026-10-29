package io.github.springauth.core.error;

/** Raised when the server-side session backend cannot confirm a safe decision. */
public class SessionUnavailableException extends RuntimeException {

    public SessionUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
