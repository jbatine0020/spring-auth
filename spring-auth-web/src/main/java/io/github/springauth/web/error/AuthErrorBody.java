package io.github.springauth.web.error;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Error payload returned by every failure of the library.
 *
 * <p>{@code code} is the stable contract clients branch on; {@code message} is a human sentence
 * that may be reworded or translated. Nothing here echoes internal detail, no stack trace, no SQL
 * state, no hint about which of several checks actually failed on the login path.
 *
 * @param status         HTTP status
 * @param error          HTTP reason phrase
 * @param code           stable error code, see {@code AuthErrorCodes}
 * @param message        sentence to show the user
 * @param path           request path
 * @param timestamp      when it happened
 * @param details        optional field-level validation errors
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthErrorBody(
        int status,
        String error,
        String code,
        String message,
        String path,
        Instant timestamp,
        Map<String, String> details) {

    public static AuthErrorBody of(int status, String error, String code, String message, String path) {
        return new AuthErrorBody(status, error, code, message, path, Instant.now(), null);
    }

    public static AuthErrorBody withDetails(int status, String error, String code, String message,
                                            String path, Map<String, String> details) {
        return new AuthErrorBody(status, error, code, message, path, Instant.now(),
                details == null || details.isEmpty() ? null : new LinkedHashMap<>(details));
    }
}
