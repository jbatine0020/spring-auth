package io.github.springauth.web.stepup;

import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.error.MfaException;
import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.service.MfaService;
import io.github.springauth.core.spi.AuthUserDirectory;
import io.github.springauth.web.support.CurrentUser;

/**
 * Verifies the step-up code of the current request.
 *
 * <p>Used by {@link StepUpInterceptor} for annotated endpoints, and callable directly from a
 * handler that decides case by case: an approval that only needs confirmation above a certain
 * amount, for instance.
 *
 * <p>No-op when step-up is disabled, when the request carries no token, or when the caller has no
 * second factor to confirm with. That last case matters: requiring a code from a user who never
 * enrols one would simply make the endpoint unreachable to them.
 */
public class StepUpEnforcer {

    private final MfaService mfaService;
    private final AuthUserDirectory userDirectory;
    private final AuthProperties.Mfa properties;

    public StepUpEnforcer(MfaService mfaService,
                          AuthUserDirectory userDirectory,
                          AuthProperties.Mfa properties) {
        this.mfaService = mfaService;
        this.userDirectory = userDirectory;
        this.properties = properties;
    }

    /**
     * @throws MfaException {@code MFA_REQUIRED} when no code is supplied, {@code MFA_INVALID_CODE}
     *                      when it is wrong, {@code MFA_LOCKED} after too many wrong ones
     */
    public void enforce(HttpServletRequest request) {
        if (!properties.isStepUpEnabled()) {
            return;
        }
        Optional<AuthUserId> caller = CurrentUser.id();
        if (caller.isEmpty()) {
            return;
        }
        Optional<AuthUser> user = userDirectory.findById(caller.get());
        if (user.isEmpty() || !user.get().requiresMfa()) {
            return;
        }
        String code = request.getHeader(properties.getStepUpHeader());
        if (code == null || code.isBlank()) {
            throw MfaException.required();
        }
        mfaService.verifyStepUp(caller.get(), code.trim(), ActionDigest.forRequest(request));
    }
}
