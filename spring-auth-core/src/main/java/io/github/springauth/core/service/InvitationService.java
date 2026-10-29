package io.github.springauth.core.service;

import java.time.Clock;
import java.time.Instant;

import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.crypto.OpaqueTokenFactory;
import io.github.springauth.core.error.InvitationException;
import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.UserInvitation;
import io.github.springauth.core.port.InvitationStore;
import io.github.springauth.core.spi.AuthMessenger;
import io.github.springauth.core.spi.AuthUserDirectory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

/**
 * Onboarding by invitation link.
 *
 * <p>The token in the link <i>is</i> the credential: whoever opens it can set the account's first
 * password. That is why it is 256 random bits, stored only as a digest, valid once, and expiring
 * after a bounded window.
 *
 * <p>The application still owns its user record. When an invitation is redeemed the library sets
 * the password and fires {@code onInvitationRedeemed}, and the application flips its own account
 * status in that callback.
 */
@Transactional
public class InvitationService {

    private static final Logger log = LoggerFactory.getLogger(InvitationService.class);

    private final InvitationStore invitationStore;
    private final AuthUserDirectory userDirectory;
    private final OpaqueTokenFactory tokenFactory;
    private final PasswordService passwordService;
    private final AuthMessenger messenger;
    private final AuthAuditor auditor;
    private final AuthProperties properties;
    private final Clock clock;

    public InvitationService(InvitationStore invitationStore,
                             AuthUserDirectory userDirectory,
                             OpaqueTokenFactory tokenFactory,
                             PasswordService passwordService,
                             AuthMessenger messenger,
                             AuthAuditor auditor,
                             AuthProperties properties,
                             Clock clock) {
        this.invitationStore = invitationStore;
        this.userDirectory = userDirectory;
        this.tokenFactory = tokenFactory;
        this.passwordService = passwordService;
        this.messenger = messenger;
        this.auditor = auditor;
        this.properties = properties;
        this.clock = clock;
    }

    /**
     * Issues an invitation and hands it to {@link AuthMessenger} for delivery.
     *
     * <p>Any previous invitation for the same user is dropped first, so resending really does
     * invalidate the old link rather than leaving two working ones.
     *
     * @return the raw token, in case the application builds the activation URL itself
     */
    public String invite(AuthUserId userId) {
        Instant now = clock.instant();
        AuthUser user = userDirectory.findById(userId).orElseThrow(InvitationException::new);

        invitationStore.deleteByUserId(userId);

        String rawToken = tokenFactory.generateRawToken();
        Instant expiresAt = now.plus(properties.getInvitation().getTtl());
        invitationStore.save(UserInvitation.issue(userId, tokenFactory.hash(rawToken), null, now, expiresAt));

        try {
            messenger.sendInvitation(user, rawToken, expiresAt);
        } catch (RuntimeException ex) {
            log.warn("spring-auth: invitation could not be delivered for userId={}", userId.value(), ex);
        }
        return rawToken;
    }

    /**
     * Non-destructive check, for the activation page to render before the user submits anything.
     * Consumes nothing.
     *
     * @throws InvitationException when the token is unknown, expired or already redeemed
     */
    @Transactional(readOnly = true)
    public AuthUser verify(String rawToken) {
        UserInvitation invitation = requireRedeemable(rawToken);
        return userDirectory.findById(invitation.getUserId()).orElseThrow(InvitationException::new);
    }

    /**
     * Redeems the invitation and sets the account's first password.
     *
     * @throws InvitationException when the token is unknown, expired or already redeemed
     * @throws io.github.springauth.core.error.PasswordException when the password breaks the policy
     */
    public AuthUser redeem(String rawToken, String chosenPassword) {
        Instant now = clock.instant();
        UserInvitation invitation = requireRedeemable(rawToken);
        AuthUser user = userDirectory.findById(invitation.getUserId())
                .orElseThrow(InvitationException::new);

        // Password policy runs before the token is consumed, so a rejected password does not
        // burn the invitation.
        passwordService.initialise(user.id(), chosenPassword, false);

        invitation.redeem(now);
        invitationStore.save(invitation);
        auditor.invitationRedeemed(user, now);
        return user;
    }

    /** Drops every pending invitation of a user, for instance when the account is disabled. */
    public void revokeFor(AuthUserId userId) {
        invitationStore.deleteByUserId(userId);
    }

    private UserInvitation requireRedeemable(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new InvitationException();
        }
        UserInvitation invitation = invitationStore.findByTokenHash(tokenFactory.hash(rawToken))
                .orElseThrow(InvitationException::new);
        if (!invitation.isRedeemable(clock.instant())) {
            throw new InvitationException();
        }
        return invitation;
    }
}
