package io.github.springauth.web.support;

import java.util.Optional;

import io.github.springauth.core.model.AuthUserId;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Reads the authenticated caller out of the security context.
 *
 * <p>Always sourced from the validated token, never from a path variable or a request body: an
 * identifier taken from the URL is whatever the caller typed, and trusting it is how endpoints end
 * up acting on someone else's account.
 */
public final class CurrentUser {

    private CurrentUser() {
        // utility
    }

    /** The subject of the current access token, empty when the caller is not authenticated. */
    public static Optional<AuthUserId> id() {
        return jwt().map(Jwt::getSubject)
                .filter(subject -> !subject.isBlank())
                .map(AuthUserId::of);
    }

    /**
     * @throws IllegalStateException when called outside an authenticated request. Reaching this
     *                               means the endpoint is missing its authorisation rule
     */
    public static AuthUserId requireId() {
        return id().orElseThrow(() -> new IllegalStateException(
                "No authenticated user in the security context"));
    }

    /** The validated access token itself, for reading application claims. */
    public static Optional<Jwt> jwt() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication instanceof JwtAuthenticationToken token
                ? Optional.of(token.getToken())
                : Optional.empty();
    }

    /** Value of a claim on the current token. */
    public static Optional<String> claim(String name) {
        return jwt().map(token -> token.getClaimAsString(name));
    }
}
