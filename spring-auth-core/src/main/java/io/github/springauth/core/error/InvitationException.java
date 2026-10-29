package io.github.springauth.core.error;

/**
 * Invitation token unknown, expired or already redeemed.
 *
 * <p>One single code covers the three cases: the token itself is the only credential the caller
 * holds, so distinguishing "expired" from "unknown" would confirm that a guessed token once
 * existed.
 */
public class InvitationException extends AuthException {

    public InvitationException() {
        super(AuthErrorCodes.INVITATION_INVALID,
                "Ce lien d'invitation est invalide ou a expiré");
    }
}
