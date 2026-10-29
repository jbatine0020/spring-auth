package io.github.springauth.web.support;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import io.github.springauth.core.config.AuthProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

/**
 * Serves the refresh token as an HttpOnly cookie.
 *
 * <p>Worth enabling for browser clients: a refresh token kept in {@code localStorage} is readable
 * by any script that manages to run on the page, and it is long-lived by design. An HttpOnly
 * cookie is not reachable from JavaScript at all, which turns a successful XSS from "permanent
 * account takeover" into "damage for the length of one access token".
 *
 * <p>{@code SameSite=Strict} and a path scoped to the API are what keep the cookie from being sent
 * along with cross-site requests; without them the same cookie becomes a CSRF vector.
 */
public class RefreshTokenCookies {

    private final AuthProperties.Session properties;

    public RefreshTokenCookies(AuthProperties.Session properties) {
        this.properties = properties;
    }

    public boolean isEnabled() {
        return properties.isRefreshCookieEnabled();
    }

    /** Writes the cookie onto the response. No-op when the cookie mode is off. */
    public void write(HttpServletResponse response, String rawRefreshToken) {
        if (!isEnabled() || rawRefreshToken == null || rawRefreshToken.isBlank()) {
            return;
        }
        ResponseCookie cookie = ResponseCookie.from(properties.getRefreshCookieName(), rawRefreshToken)
                .httpOnly(true)
                .secure(properties.isRefreshCookieSecure())
                .sameSite(properties.getRefreshCookieSameSite())
                .path(properties.getRefreshCookiePath())
                .maxAge(properties.getRefreshTtl())
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    /** Clears the cookie on logout. */
    public void clear(HttpServletResponse response) {
        if (!isEnabled()) {
            return;
        }
        ResponseCookie cookie = ResponseCookie.from(properties.getRefreshCookieName(), "")
                .httpOnly(true)
                .secure(properties.isRefreshCookieSecure())
                .sameSite(properties.getRefreshCookieSameSite())
                .path(properties.getRefreshCookiePath())
                .maxAge(0)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    /**
     * Resolves the refresh token, preferring the body and falling back to the cookie.
     *
     * <p>The body wins so that a non-browser client is never affected by a stale cookie.
     */
    public String resolve(HttpServletRequest request, String fromBody) {
        if (fromBody != null && !fromBody.isBlank()) {
            return fromBody;
        }
        if (!isEnabled() || request.getCookies() == null) {
            return null;
        }
        for (jakarta.servlet.http.Cookie cookie : request.getCookies()) {
            if (properties.getRefreshCookieName().equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
