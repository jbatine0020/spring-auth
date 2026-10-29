package io.github.springauth.core.model;

import java.util.Objects;
import java.util.UUID;

/**
 * Identifier of an authenticated principal, as seen by spring-auth.
 *
 * <p>The value is kept as an opaque {@link String} on purpose: it ends up verbatim in the
 * {@code sub} claim of every issued JWT, and host applications identify their users with
 * UUIDs, numeric ids or external references depending on the project. The library never
 * parses it, it only compares and stores it.
 *
 * @param value non-blank identifier, at most 64 characters (the persisted column width)
 */
public record AuthUserId(String value) {

    public static final int MAX_LENGTH = 64;

    public AuthUserId {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("AuthUserId value is required");
        }
        value = value.trim();
        if (value.length() > MAX_LENGTH) {
            throw new IllegalArgumentException(
                    "AuthUserId must not exceed " + MAX_LENGTH + " characters, got " + value.length());
        }
    }

    public static AuthUserId of(String value) {
        return new AuthUserId(value);
    }

    public static AuthUserId of(UUID value) {
        return new AuthUserId(Objects.requireNonNull(value, "value is required").toString());
    }

    /**
     * Reads the identifier back as a UUID.
     *
     * @throws IllegalStateException when the host application does not use UUID identifiers
     */
    public UUID toUUID() {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("AuthUserId '" + value + "' is not a UUID", ex);
        }
    }

    @Override
    public String toString() {
        return value;
    }
}
