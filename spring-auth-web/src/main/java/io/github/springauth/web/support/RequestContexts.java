package io.github.springauth.web.support;

import jakarta.servlet.http.HttpServletRequest;
import io.github.springauth.core.model.RequestContext;

/**
 * Builds the caller metadata attached to authentication attempts.
 *
 * <p>The address is the one the connection actually came from. {@code X-Forwarded-For} is
 * deliberately ignored here: it is a client-supplied header, so honouring it blindly lets an
 * attacker write whatever address they like into the audit trail and, worse, sidestep any
 * per-address rule built on top of it. If your application sits behind a trusted proxy, configure
 * {@code server.forward-headers-strategy=framework} so the servlet container resolves the real
 * address before it reaches this code.
 */
public final class RequestContexts {

    private static final int MAX_USER_AGENT_LENGTH = 512;

    private RequestContexts() {
        // utility
    }

    public static RequestContext from(HttpServletRequest request) {
        if (request == null) {
            return RequestContext.empty();
        }
        return RequestContext.of(clientAddress(request), userAgent(request));
    }

    private static String clientAddress(HttpServletRequest request) {
        String address = request.getRemoteAddr();
        return address == null || address.isBlank() ? null : address;
    }

    private static String userAgent(HttpServletRequest request) {
        String value = request.getHeader("User-Agent");
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.length() <= MAX_USER_AGENT_LENGTH
                ? value
                : value.substring(0, MAX_USER_AGENT_LENGTH);
    }
}
