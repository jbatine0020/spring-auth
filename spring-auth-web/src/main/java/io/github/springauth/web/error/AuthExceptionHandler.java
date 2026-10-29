package io.github.springauth.web.error;

import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import io.github.springauth.core.error.AuthErrorCodes;
import io.github.springauth.core.error.AuthException;
import io.github.springauth.core.error.InternalAuthException;
import io.github.springauth.core.error.RateLimitedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Turns library exceptions into HTTP responses.
 *
 * <p>Ordered ahead of an application's own advice so its generic {@code Exception} handler does not
 * swallow these into a 500. An application that wants different wording maps the {@code code}
 * itself; it does not need to replace this class.
 *
 * <p>Two deliberate choices in the mapping. Authentication failures all answer 401 with the same
 * code, whatever went wrong, because a differentiated status is an enumeration oracle. And the
 * server-side log keeps the detail the response withholds, so operators lose nothing.
 */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE + 100)
public class AuthExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(AuthExceptionHandler.class);

    @ExceptionHandler(RateLimitedException.class)
    public ResponseEntity<AuthErrorBody> onRateLimited(RateLimitedException ex,
                                                       HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header(HttpHeaders.RETRY_AFTER, String.valueOf(ex.getRetryAfterSeconds()))
                .body(body(HttpStatus.TOO_MANY_REQUESTS, ex.getCode(), ex.getMessage(), request));
    }

    @ExceptionHandler(InternalAuthException.class)
    public ResponseEntity<AuthErrorBody> onInternalAuth(InternalAuthException ex,
                                                        HttpServletRequest request) {
        // The reason names the peer and the exact failure: useful to an operator, a gift to an
        // attacker. It stays in the log.
        log.warn("spring-auth: service-to-service authentication refused, {}", ex.getReason());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(body(HttpStatus.UNAUTHORIZED, ex.getCode(), ex.getMessage(), request));
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<AuthErrorBody> onAuthException(AuthException ex, HttpServletRequest request) {
        HttpStatus status = statusFor(ex.getCode());
        if (status.is5xxServerError()) {
            log.error("spring-auth: unexpected failure with code {}", ex.getCode(), ex);
        }
        return ResponseEntity.status(status)
                .body(body(status, ex.getCode(), ex.getMessage(), request));
    }

    /** Bean Validation failures on the bundled request payloads. */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<AuthErrorBody> onValidation(MethodArgumentNotValidException ex,
                                                      HttpServletRequest request) {
        Map<String, String> details = new LinkedHashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            details.putIfAbsent(error.getField(), error.getDefaultMessage());
        }
        return ResponseEntity.badRequest().body(AuthErrorBody.withDetails(
                HttpStatus.BAD_REQUEST.value(), HttpStatus.BAD_REQUEST.getReasonPhrase(),
                "VALIDATION_FAILED", "Requête invalide", request.getRequestURI(), details));
    }

    /**
     * Maps a stable code to its status.
     *
     * <p>Everything on the authentication path answers 401 so the response body is the only place
     * a legitimate client learns anything, and even there the codes are coarse.
     */
    private static HttpStatus statusFor(String code) {
        return switch (code) {
            case AuthErrorCodes.LOGIN_INVALID,
                 AuthErrorCodes.ACCOUNT_LOCKED,
                 AuthErrorCodes.MFA_REQUIRED,
                 AuthErrorCodes.MFA_INVALID_CODE,
                 AuthErrorCodes.MFA_CHALLENGE_INVALID,
                 AuthErrorCodes.REFRESH_TOKEN_INVALID,
                 AuthErrorCodes.REFRESH_TOKEN_REPLAY,
                 AuthErrorCodes.SESSION_REVOKED,
                 AuthErrorCodes.INTERNAL_AUTH_FAILED -> HttpStatus.UNAUTHORIZED;
            case AuthErrorCodes.MFA_LOCKED,
                 AuthErrorCodes.RATE_LIMITED -> HttpStatus.TOO_MANY_REQUESTS;
            case AuthErrorCodes.PASSWORD_CHANGE_REQUIRED -> HttpStatus.FORBIDDEN;
            case AuthErrorCodes.MFA_NOT_ENROLLED,
                 AuthErrorCodes.ROLE_ALREADY_EXISTS -> HttpStatus.CONFLICT;
            case AuthErrorCodes.ROLE_NOT_FOUND -> HttpStatus.NOT_FOUND;
            default -> HttpStatus.BAD_REQUEST;
        };
    }

    private static AuthErrorBody body(HttpStatus status, String code, String message,
                                      HttpServletRequest request) {
        return AuthErrorBody.of(status.value(), status.getReasonPhrase(), code, message,
                request.getRequestURI());
    }
}
