package io.github.springauth.core.service;

import io.github.springauth.core.identity.ExternalAuthenticationService;
import io.github.springauth.core.identity.IdentityProviderException;
import io.github.springauth.core.identity.IdentityUserMirror;
import io.github.springauth.core.identity.ApplicationUserStore;
import io.github.springauth.core.port.MfaCredentialStore;
import org.springframework.transaction.annotation.Transactional;
import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.MfaRequirement;
import io.github.springauth.core.model.OtpChannel;
import io.github.springauth.core.model.RequestContext;
import java.util.Map;

/** Application boundary for external-provider login; token/MFA issuance is intentionally explicit. */
@Transactional
public class ExternalLoginService {
    private final ExternalAuthenticationService externalAuthentication;
    private final MfaChallengeIssuer challengeIssuer;
    private final SessionService sessionService;
    private final ApplicationUserStore users;
    private final MfaCredentialStore mfaCredentials;
    private final LoginOtpService loginOtpService;

    public ExternalLoginService(ExternalAuthenticationService externalAuthentication,
                                MfaChallengeIssuer challengeIssuer, SessionService sessionService,
                                ApplicationUserStore users, MfaCredentialStore mfaCredentials,
                                LoginOtpService loginOtpService) {
        this.externalAuthentication = externalAuthentication;
        this.challengeIssuer = challengeIssuer;
        this.sessionService = sessionService;
        this.users = users;
        this.mfaCredentials = mfaCredentials;
        this.loginOtpService = loginOtpService;
    }

    public IdentityUserMirror authenticate(String login, char[] password)
            throws IdentityProviderException {
        return externalAuthentication.authenticate(login, password);
    }

    public AuthUser authenticateUser(String login, char[] password)
            throws IdentityProviderException {
        IdentityUserMirror mirror = authenticate(login, password);
        var local = users.findByLogin(login).orElseThrow();
        // The mirror identifies the directory record.  All spring-auth state (MFA, sessions and
        // authorizations) belongs to the provisioned local user, whose identifier may differ
        // from the mirror identifier after a migration.
        return AuthUser.builder(AuthUserId.of(local.id().toString()), mirror.login())
                .email(mirror.email()).phoneNumber(local.phoneNumber()).displayName(mirror.displayName())
                .mfaRequirement(local.mfaMethod() == io.github.springauth.core.identity.MfaMethod.NONE ? MfaRequirement.NOT_APPLICABLE : MfaRequirement.REQUIRED)
                .roleCodes(local.roleCodes()).extraClaims(Map.of("mfaMethod", local.mfaMethod().name())).build();
    }

    public ExternalLoginResult authenticateForLogin(String login, char[] password)
            throws IdentityProviderException {
        AuthUser user = authenticateUser(login, password);
        var local = users.findByLogin(login).orElseThrow();
        if (local.mfaMethod() == io.github.springauth.core.identity.MfaMethod.TOTP && mfaCredentials.findByUserId(user.id())
                .filter(io.github.springauth.core.model.MfaCredential::isConfirmed).isEmpty()) {
            return ExternalLoginResult.mfaEnrollmentRequired(user, challengeIssuer.issueEnrollment(user.id()));
        }
        if (local.mfaMethod() == io.github.springauth.core.identity.MfaMethod.EMAIL_OTP || local.mfaMethod() == io.github.springauth.core.identity.MfaMethod.SMS_OTP) {
            var challenge = loginOtpService.issue(user,
                    local.mfaMethod() == io.github.springauth.core.identity.MfaMethod.SMS_OTP ? OtpChannel.SMS : OtpChannel.EMAIL);
            return ExternalLoginResult.otpRequired(user, challenge);
        }
        return user.requiresMfa()
                ? ExternalLoginResult.mfaRequired(user, challengeIssuer.issue(user.id()))
                : ExternalLoginResult.authenticated(user);
    }

    public AuthTokens authenticateAndOpenSession(String login, char[] password)
            throws IdentityProviderException {
        ExternalLoginResult result = authenticateForLogin(login, password);
        if (result.status() != ExternalLoginResult.Status.AUTHENTICATED) {
            throw new IllegalStateException("MFA is required before session issuance");
        }
        return sessionService.openSession(result.user());
    }

    public AuthTokens openSession(ExternalLoginResult result) {
        if (result.status() != ExternalLoginResult.Status.AUTHENTICATED) {
            throw new IllegalStateException("MFA is required before session issuance");
        }
        return sessionService.openSession(result.user());
    }

    public AuthTokens openSession(ExternalLoginResult result, RequestContext context) {
        if (result.status() != ExternalLoginResult.Status.AUTHENTICATED) {
            throw new IllegalStateException("MFA is required before session issuance");
        }
        return sessionService.openSession(result.user(), context);
    }
}
