package io.github.springauth.web.controller;

/**
 * Permissions guarding the bundled administration endpoints.
 *
 * <p>Seed them into the roles of your own administrators. Nothing in the library grants them, so
 * an application that never assigns them simply has no administration API reachable, which is the
 * safe default.
 */
public final class AuthPermissions {

    /** Set or reset another user's password, unlock their account. */
    public static final String USERS_PASSWORD = "auth:users:password";

    /** Reset another user's second factor. */
    public static final String USERS_MFA = "auth:users:mfa";

    /** Close another user's sessions. */
    public static final String USERS_SESSIONS = "auth:users:sessions";

    /** Send and revoke invitations. */
    public static final String USERS_INVITE = "auth:users:invite";

    /** Read roles and their permissions. */
    public static final String ROLES_READ = "auth:roles:read";

    /** Create, modify and archive roles. */
    public static final String ROLES_WRITE = "auth:roles:write";

    private AuthPermissions() {
        // constants holder
    }
}
