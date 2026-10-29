package io.github.springauth.core.identity;

import org.springframework.transaction.annotation.Transactional;

/** Authenticates against an external provider and synchronizes the local identity mirror. */
public class ExternalAuthenticationService {
    private final IdentityProvider provider;
    private final IdentityMirrorService mirrorService;
    private final ApplicationUserStore users;

    public ExternalAuthenticationService(IdentityProvider provider, IdentityMirrorService mirrorService,
                                         ApplicationUserStore users) {
        this.provider = provider;
        this.mirrorService = mirrorService;
        this.users = users;
    }

    @Transactional
    public IdentityUserMirror authenticate(String login, char[] password) throws IdentityProviderException {
        ApplicationUser local = users.findByLogin(login)
                .filter(ApplicationUser::canAttemptLogin)
                .filter(user -> !user.roleCodes().isEmpty())
                .orElseThrow(() -> new IdentityProviderException(
                        IdentityProviderException.Kind.INVALID_CREDENTIALS, "identity is not authorized"));
        IdentityAuthenticationResult identity = provider.authenticate(login, password);
        if (!local.externalSubject().equals(identity.externalSubject())) {
            throw new IdentityProviderException(IdentityProviderException.Kind.INVALID_RESPONSE,
                    "directory identity does not match the provisioned account");
        }
        return mirrorService.synchronizeExisting(provider, identity)
                .orElseThrow(() -> new IdentityProviderException(
                        IdentityProviderException.Kind.INVALID_RESPONSE,
                        "identity has not been provisioned locally"));
    }
}
