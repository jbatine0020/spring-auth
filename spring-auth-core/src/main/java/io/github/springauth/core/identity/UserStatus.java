package io.github.springauth.core.identity;

/** Lifecycle state of a provisioned application user. Values are part of the public JSON contract. */
public enum UserStatus {
    ACTIVE,
    PENDING_MFA,
    DISABLED,
    LOCKED;

    public static UserStatus parse(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("User status is required");
        }
        try {
            return valueOf(value.trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Unsupported user status: " + value, ex);
        }
    }
}
