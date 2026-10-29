package io.github.springauth.core.spi;

import java.util.Optional;

import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;

/**
 * The one interface a host application must implement.
 *
 * <p>spring-auth owns credentials, factors, sessions and reset requests, but never the user
 * record: applications model it with companies, branches, agents or customers, and duplicating it
 * inside the library would force a synchronisation problem on everyone. Instead the library asks
 * for the projection it needs, when it needs it.
 *
 * <p>Both lookups are on the hot path of every login, so back them with an indexed query.
 *
 * <h2>Example</h2>
 * <pre>{@code
 * @Component
 * class JpaAuthUserDirectory implements AuthUserDirectory {
 *
 *     private final UserRepository users;
 *
 *     @Override
 *     public Optional<AuthUser> findByLogin(String login) {
 *         return users.findByEmailIgnoreCase(login).map(this::toAuthUser);
 *     }
 *
 *     @Override
 *     public Optional<AuthUser> findById(AuthUserId id) {
 *         return users.findById(UUID.fromString(id.value())).map(this::toAuthUser);
 *     }
 *
 *     private AuthUser toAuthUser(UserEntity entity) {
 *         return AuthUser.builder(AuthUserId.of(entity.getId()), entity.getEmail())
 *                 .email(entity.getEmail())
 *                 .phoneNumber(entity.getPhone())
 *                 .displayName(entity.getFullName())
 *                 .status(entity.isEnabled() ? AuthUserStatus.ACTIVE : AuthUserStatus.DISABLED)
 *                 .mfaRequirement(entity.isStaff() ? MfaRequirement.NOT_APPLICABLE : MfaRequirement.REQUIRED)
 *                 .tenantId(entity.getCompanyId())
 *                 .roleCodes(entity.getRoleCodes())
 *                 .build();
 *     }
 * }
 * }</pre>
 */
public interface AuthUserDirectory {

    /**
     * Resolves the value typed in the login form.
     *
     * <p>Implementations decide what a login is: an email, a username, an employee number, or any
     * of them. Matching should be case-insensitive for email-like identifiers.
     *
     * @return the user, or empty when nothing matches. The caller answers with a generic error
     *         either way
     */
    Optional<AuthUser> findByLogin(String login);

    /** Resolves a user from a token subject, a reset request or an invitation. */
    Optional<AuthUser> findById(AuthUserId id);
}
