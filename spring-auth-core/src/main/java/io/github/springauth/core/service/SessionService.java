package io.github.springauth.core.service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.crypto.OpaqueTokenFactory;
import io.github.springauth.core.error.SessionException;
import io.github.springauth.core.jwt.JwtIssuer;
import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.RequestContext;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.RefreshToken;
import io.github.springauth.core.model.RequestContext;
import io.github.springauth.core.port.AccessTokenRevocationStore;
import io.github.springauth.core.port.CredentialsStore;
import io.github.springauth.core.port.RefreshTokenStore;
import io.github.springauth.core.spi.AuthUserDirectory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

/**
 * Opens, refreshes and closes sessions.
 *
 * <p>The refresh endpoint is where most of the security of a long-lived session sits, so the
 * rules are worth spelling out:
 * <ul>
 *   <li><b>Rotation</b>: every refresh mints a new token and revokes the one presented, so a
 *       captured token is only usable until the real client refreshes.</li>
 *   <li><b>Family invalidation</b>: presenting an already-revoked token means two parties hold
 *       the same secret. The entire family is revoked, which logs out attacker and victim alike
 *       and turns a silent compromise into a visible re-authentication.</li>
 *   <li><b>Access revocation</b>: refresh tokens live in the database and can be withdrawn, but
 *       access tokens are self-contained. Closing sessions therefore also writes a revocation
 *       stamp that the request filter checks.</li>
 * </ul>
 */
@Transactional
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);

    private final RefreshTokenStore refreshTokenStore;
    private final CredentialsStore credentialsStore;
    private final AccessTokenRevocationStore revocationStore;
    private final AuthUserDirectory userDirectory;
    private final OpaqueTokenFactory tokenFactory;
    private final JwtIssuer jwtIssuer;
    private final PermissionResolver permissionResolver;
    private final AuthAuditor auditor;
    private final AuthProperties properties;
    private final Clock clock;

    public SessionService(RefreshTokenStore refreshTokenStore,
                          CredentialsStore credentialsStore,
                          AccessTokenRevocationStore revocationStore,
                          AuthUserDirectory userDirectory,
                          OpaqueTokenFactory tokenFactory,
                          JwtIssuer jwtIssuer,
                          PermissionResolver permissionResolver,
                          AuthAuditor auditor,
                          AuthProperties properties,
                          Clock clock) {
        this.refreshTokenStore = refreshTokenStore;
        this.credentialsStore = credentialsStore;
        this.revocationStore = revocationStore;
        this.userDirectory = userDirectory;
        this.tokenFactory = tokenFactory;
        this.jwtIssuer = jwtIssuer;
        this.permissionResolver = permissionResolver;
        this.auditor = auditor;
        this.properties = properties;
        this.clock = clock;
    }

    /** Opens a brand-new session: fresh refresh family plus a first access token. */
    public AuthTokens openSession(AuthUser user) {
        Instant now = clock.instant();
        String rawRefresh = tokenFactory.generateRawToken();
        RefreshToken refreshToken = RefreshToken.issueNewSession(
                user.id(), tokenFactory.hash(rawRefresh), properties.getSession().getRefreshTtl(), now);
        refreshTokenStore.save(refreshToken);
        return AuthTokens.of(issueAccessToken(user, now), rawRefresh);
    }

    public AuthTokens openSession(AuthUser user, RequestContext context) {
        AuthTokens tokens = openSession(user);
        auditor.loginSucceeded(user, context, clock.instant());
        return tokens;
    }

    /**
     * Exchanges a refresh token for a new pair.
     *
     * @throws SessionException {@code REFRESH_TOKEN_REPLAY} when the token was already rotated,
     *                          in which case the family is revoked before the exception leaves this method;
     *                          {@code REFRESH_TOKEN_INVALID} when it is unknown or expired
     */
    @Transactional(noRollbackFor = SessionException.class)
    public AuthTokens refresh(String rawRefreshToken, RequestContext context) {
        Instant now = clock.instant();
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw SessionException.invalidRefreshToken();
        }
        RefreshToken presented = refreshTokenStore.findByTokenHashForUpdate(tokenFactory.hash(rawRefreshToken))
                .orElseThrow(SessionException::invalidRefreshToken);

        if (presented.isRevoked()) {
            // Two holders of the same secret. Burn the whole family rather than this one row:
            // the attacker may already own a newer token in the same chain.
            int revoked = refreshTokenStore.revokeFamily(presented.getFamilyId(), now);
            stampAccessRevocation(presented.getUserId(), now);
            log.warn("spring-auth: refresh token replay for userId={}, {} tokens revoked",
                    presented.getUserId().value(), revoked);
            auditor.refreshTokenReplayDetected(presented.getUserId(), context, now);
            throw SessionException.replayDetected();
        }
        if (presented.isExpiredAt(now)) {
            throw SessionException.invalidRefreshToken();
        }

        AuthUser user = userDirectory.findById(presented.getUserId())
                .orElseThrow(SessionException::invalidRefreshToken);
        if (!user.canAuthenticate()) {
            // The account was disabled while the session was alive: close it now.
            refreshTokenStore.revokeAllForUser(user.id(), now);
            throw SessionException.invalidRefreshToken();
        }

        String rawRefresh = tokenFactory.generateRawToken();
        RefreshToken successor = RefreshToken.issueWithinFamily(
                user.id(), presented.getFamilyId(), tokenFactory.hash(rawRefresh),
                properties.getSession().getRefreshTtl(), now);
        refreshTokenStore.save(successor);
        presented.rotateTo(successor.getId(), now);
        refreshTokenStore.save(presented);

        return AuthTokens.of(issueAccessToken(user, now), rawRefresh);
    }

    /**
     * Closes one session. Idempotent: an unknown or already-revoked token is not an error, since
     * the caller's intent, "this session is over", already holds.
     */
    public void logout(String rawRefreshToken) {
        Instant now = clock.instant();
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            return;
        }
        refreshTokenStore.findByTokenHash(tokenFactory.hash(rawRefreshToken)).ifPresent(token -> {
            token.revoke(now);
            refreshTokenStore.save(token);
            auditor.logout(token.getUserId(), now);
        });
    }

    /**
     * Closes every session of a user and invalidates their outstanding access tokens.
     *
     * <p>Call it after a password change, an administrative lockout, or a "log me out everywhere"
     * action.
     *
     * @return how many refresh tokens were revoked
     */
    public int revokeAllSessions(AuthUserId userId) {
        Instant now = clock.instant();
        int revoked = refreshTokenStore.revokeAllForUser(userId, now);
        stampAccessRevocation(userId, now);
        return revoked;
    }

    /** Issues an access token for an already-authenticated user. */
    public JwtIssuer.IssuedToken issueAccessToken(AuthUser user, Instant now) {
        Duration maxAge = properties.getPassword().getMaxAge();
        boolean mustChangePassword = credentialsStore.findByUserId(user.id())
                .map(credentials -> credentials.requiresPasswordChange(now, maxAge))
                .orElse(false);
        return jwtIssuer.issueAccessToken(user, permissionResolver.resolve(user), mustChangePassword);
    }

    private void stampAccessRevocation(AuthUserId userId, Instant now) {
        // The stamp must outlive every token already in flight, hence the configured skew on top
        // of the access TTL.
        Duration ttl = jwtIssuer.getAccessTtl().plus(properties.getJwt().getRevocationSkew());
        try {
            revocationStore.revokeSince(userId, now.getEpochSecond(), ttl);
        } catch (RuntimeException ex) {
            // Refresh tokens are already revoked, so the session cannot be renewed; the worst case
            // is one access token staying valid for the rest of its short life.
            log.error("spring-auth: could not stamp access-token revocation for userId={}",
                    userId.value(), ex);
        }
    }

    /** Looks a session up by its raw refresh token. Read-only helper for diagnostics. */
    @Transactional(readOnly = true)
    public Optional<RefreshToken> findSession(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            return Optional.empty();
        }
        return refreshTokenStore.findByTokenHash(tokenFactory.hash(rawRefreshToken));
    }
}
