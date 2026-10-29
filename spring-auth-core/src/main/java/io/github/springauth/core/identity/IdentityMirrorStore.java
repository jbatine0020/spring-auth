package io.github.springauth.core.identity;

import java.util.Optional;

/** Persistence port for the local identity mirror. */
public interface IdentityMirrorStore {

    Optional<IdentityUserMirror> find(String providerId, String externalSubject);
    Optional<IdentityUserMirror> findByLogin(String login);
    Optional<IdentityUserMirror> findById(java.util.UUID id);

    IdentityUserMirror save(IdentityUserMirror mirror);
}
