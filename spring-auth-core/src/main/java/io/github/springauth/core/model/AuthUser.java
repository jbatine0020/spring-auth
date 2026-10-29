package io.github.springauth.core.model;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Read-only projection of a host application user, supplied through
 * {@link io.github.springauth.core.spi.AuthUserDirectory}.
 *
 * <p>spring-auth deliberately does not own the user aggregate: every application models
 * users differently (companies, branches, agents, customers). It only needs the handful of
 * attributes below to authenticate someone, decide whether MFA applies, and mint a token.
 *
 * @param id             stable identifier, becomes the JWT {@code sub}
 * @param login          value typed in the login form (email, username, employee number)
 * @param email          address used for password reset and invitation links, may be null
 * @param phoneNumber    E.164 number used for the password-reset OTP, may be null
 * @param displayName    human-readable name for notifications, may be null
 * @param status         account status, gates authentication
 * @param mfaRequirement whether this user must carry a second factor
 * @param tenantId       optional tenant/organisation discriminator, emitted as a JWT claim
 * @param roleCodes      role codes owned by the user, resolved to permissions by the RBAC module
 * @param extraClaims    additional claims copied verbatim into issued access tokens
 */
public record AuthUser(
        AuthUserId id,
        String login,
        String email,
        String phoneNumber,
        String displayName,
        AuthUserStatus status,
        MfaRequirement mfaRequirement,
        String tenantId,
        Set<String> roleCodes,
        Map<String, Object> extraClaims) {

    public AuthUser {
        Objects.requireNonNull(id, "id is required");
        Objects.requireNonNull(status, "status is required");
        Objects.requireNonNull(mfaRequirement, "mfaRequirement is required");
        if (login == null || login.isBlank()) {
            throw new IllegalArgumentException("login is required");
        }
        roleCodes = roleCodes == null ? Set.of() : Set.copyOf(new LinkedHashSet<>(roleCodes));
        extraClaims = extraClaims == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(extraClaims));
    }

    /** Minimal user: active, no MFA, no roles. Handy for tests and simple applications. */
    public static AuthUser of(AuthUserId id, String login, String email) {
        return new AuthUser(id, login, email, null, null,
                AuthUserStatus.ACTIVE, MfaRequirement.NOT_APPLICABLE, null, Set.of(), Map.of());
    }

    public static Builder builder(AuthUserId id, String login) {
        return new Builder(id, login);
    }

    public boolean canAuthenticate() {
        return status == AuthUserStatus.ACTIVE;
    }

    public boolean requiresMfa() {
        return mfaRequirement == MfaRequirement.REQUIRED;
    }

    /** Fluent builder. The record has too many optional attributes for a readable constructor call. */
    public static final class Builder {

        private final AuthUserId id;
        private final String login;
        private String email;
        private String phoneNumber;
        private String displayName;
        private AuthUserStatus status = AuthUserStatus.ACTIVE;
        private MfaRequirement mfaRequirement = MfaRequirement.NOT_APPLICABLE;
        private String tenantId;
        private Set<String> roleCodes = Set.of();
        private Map<String, Object> extraClaims = Map.of();

        private Builder(AuthUserId id, String login) {
            this.id = id;
            this.login = login;
        }

        public Builder email(String value) {
            this.email = value;
            return this;
        }

        public Builder phoneNumber(String value) {
            this.phoneNumber = value;
            return this;
        }

        public Builder displayName(String value) {
            this.displayName = value;
            return this;
        }

        public Builder status(AuthUserStatus value) {
            this.status = value;
            return this;
        }

        public Builder mfaRequirement(MfaRequirement value) {
            this.mfaRequirement = value;
            return this;
        }

        public Builder tenantId(String value) {
            this.tenantId = value;
            return this;
        }

        public Builder roleCodes(Set<String> value) {
            this.roleCodes = value;
            return this;
        }

        public Builder extraClaims(Map<String, Object> value) {
            this.extraClaims = value;
            return this;
        }

        public AuthUser build() {
            return new AuthUser(id, login, email, phoneNumber, displayName,
                    status, mfaRequirement, tenantId, roleCodes, extraClaims);
        }
    }
}
