package io.github.springauth.web.support;

import java.time.Duration;

import org.springframework.http.ResponseCookie;

/** Builds the hardened browser cookie carrying the opaque server-session id. */
public final class ServerSessionCookies {

    public static final String NAME = "__Host-spring_auth_session";

    private ServerSessionCookies() {
    }

    public static ResponseCookie issue(String sessionId, Duration maxAge) {
        return ResponseCookie.from(NAME, sessionId)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/")
                .maxAge(maxAge)
                .build();
    }

    public static ResponseCookie clear() {
        return issue("", Duration.ZERO);
    }
}
