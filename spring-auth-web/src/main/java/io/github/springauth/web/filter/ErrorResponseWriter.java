package io.github.springauth.web.filter;

import java.io.IOException;

import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import io.github.springauth.web.error.AuthErrorBody;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

/**
 * Writes an error body straight onto the response, for the filters that run before the dispatcher.
 *
 * <p>A filter cannot let an exception propagate the way a controller can: nothing downstream would
 * catch it, the container would render its own error page, and that page leaks a stack trace. So
 * the response is written here, in the same shape controllers produce, keeping the client contract
 * uniform.
 */
public class ErrorResponseWriter {

    private final ObjectMapper objectMapper;

    public ErrorResponseWriter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public void write(HttpServletRequest request, HttpServletResponse response,
                      HttpStatus status, String code, String message) throws IOException {
        write(request, response, status, code, message, null);
    }

    /**
     * @param retryAfterSeconds emitted as {@code Retry-After} when not null
     */
    public void write(HttpServletRequest request, HttpServletResponse response,
                      HttpStatus status, String code, String message,
                      Long retryAfterSeconds) throws IOException {
        // reset() drops anything a previous stage may have started writing, so the body is exactly
        // this payload and the Content-Length matches.
        response.reset();
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        if (retryAfterSeconds != null) {
            response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
        }
        AuthErrorBody body = AuthErrorBody.of(status.value(), status.getReasonPhrase(), code,
                message, request.getRequestURI());
        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
