package io.github.springauth.core.port;

import java.time.Instant;
import java.util.Optional;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.UserInvitation;

/** Persistence of onboarding invitations. */
public interface InvitationStore {

    Optional<UserInvitation> findByTokenHash(String tokenHash);

    UserInvitation save(UserInvitation invitation);

    /** Invalidates every pending invitation of a user. Resending must void the previous link. */
    void deleteByUserId(AuthUserId userId);

    int deleteExpiredBefore(Instant before);
}
