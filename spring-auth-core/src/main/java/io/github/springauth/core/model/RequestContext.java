package io.github.springauth.core.model;

/**
 * Caller metadata attached to authentication attempts.
 *
 * <p>Kept as a plain value so the core services stay free of the servlet API; the web module fills
 * it in from the current request.
 *
 * @param ipAddress client address, may be null when the call does not come from HTTP
 * @param userAgent client user agent, may be null
 */
public record RequestContext(String ipAddress, String userAgent) {

    private static final RequestContext EMPTY = new RequestContext(null, null);

    /** No metadata. Internal calls, batch jobs, tests. */
    public static RequestContext empty() {
        return EMPTY;
    }

    public static RequestContext of(String ipAddress, String userAgent) {
        return new RequestContext(ipAddress, userAgent);
    }
}
