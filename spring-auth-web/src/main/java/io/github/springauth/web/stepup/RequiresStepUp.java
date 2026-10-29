package io.github.springauth.web.stepup;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires a fresh MFA confirmation for this endpoint, on top of being authenticated.
 *
 * <p>Put it on the handful of actions where a stolen session is not an acceptable risk: moving
 * money, changing a payout account, granting privileges. The caller sends a current TOTP code in
 * the {@code X-Mfa-Code} header, and the code is consumed: one action, one code, so an observed
 * code cannot be reused for a second one.
 *
 * <p>Enforcement happens before the handler runs, so a missing or wrong code costs no business
 * write. Only users who actually carry a second factor are subject to it; the check is skipped for
 * users whose {@code MfaRequirement} is {@code NOT_APPLICABLE}, otherwise the endpoint would be
 * unreachable to them.
 *
 * <p>Placed on a class, it covers every endpoint of that controller.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface RequiresStepUp {
}
