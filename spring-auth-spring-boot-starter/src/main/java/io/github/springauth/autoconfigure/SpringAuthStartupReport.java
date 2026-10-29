package io.github.springauth.autoconfigure;

import java.util.ArrayList;
import java.util.List;

import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.port.AccessTokenRevocationStore;
import io.github.springauth.core.port.RateLimiter;
import io.github.springauth.core.support.InMemoryAccessTokenRevocationStore;
import io.github.springauth.core.support.InMemoryRateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;

/**
 * Reports, once at startup, the configuration choices that are fine in development and dangerous
 * in production.
 *
 * <p>These are the settings that fail silently: nothing breaks, tests pass, and the weakness only
 * shows up when someone attacks it or when a second replica is added. A line in the boot log is
 * the cheapest place to catch them.
 */
public class SpringAuthStartupReport {

    private static final Logger log = LoggerFactory.getLogger(SpringAuthStartupReport.class);

    private final AuthProperties properties;
    private final RateLimiter rateLimiter;
    private final AccessTokenRevocationStore revocationStore;
    private final boolean messengerConfigured;

    public SpringAuthStartupReport(AuthProperties properties,
                                   RateLimiter rateLimiter,
                                   AccessTokenRevocationStore revocationStore,
                                   boolean messengerConfigured) {
        this.properties = properties;
        this.rateLimiter = rateLimiter;
        this.revocationStore = revocationStore;
        this.messengerConfigured = messengerConfigured;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void report() {
        List<String> warnings = new ArrayList<>();

        if (!properties.getRateLimit().isEnabled()) {
            warnings.add("rate limiting is disabled, brute-force protection on /login is off");
        }
        if (!properties.getMfa().isStepUpEnabled()) {
            warnings.add("step-up MFA is disabled, @RequiresStepUp endpoints are not protected");
        }
        if (properties.getPassword().getBcryptCost() < 10) {
            warnings.add("BCrypt cost is " + properties.getPassword().getBcryptCost()
                    + ", below the recommended 10, offline cracking gets cheaper");
        }
        if (properties.getPassword().getHistorySize() <= 0) {
            warnings.add("password history is disabled, users may cycle back to a known password");
        }
        if (rateLimiter instanceof InMemoryRateLimiter) {
            warnings.add("the rate limiter is in-memory, with N replicas the effective quota is N "
                    + "times the configured one. Add Spring Data Redis to share it");
        }
        if (revocationStore instanceof InMemoryAccessTokenRevocationStore) {
            warnings.add("token revocation is in-memory, a logout only applies to the instance that "
                    + "handled it. Add Spring Data Redis to share it");
        }
        if (!messengerConfigured) {
            if (properties.getPasswordReset().isEnabled()) {
                warnings.add("no AuthMessenger bean, password reset links and codes are generated "
                        + "but never delivered");
            } else if (properties.getInvitation().isEnabled()) {
                warnings.add("no AuthMessenger bean, invitation links are generated but never delivered");
            }
        }
        if (properties.getPasswordReset().isEnabled() && !properties.getPasswordReset().isRequireOtp()) {
            warnings.add("password reset runs link-only, the emailed link is the single factor");
        }
        if (properties.getSession().isRefreshCookieEnabled()
                && !properties.getSession().isRefreshCookieSecure()) {
            warnings.add("the refresh cookie is served without the Secure flag, it will travel over "
                    + "plain HTTP");
        }

        if (warnings.isEmpty()) {
            log.info("spring-auth: started with a hardened configuration");
            return;
        }
        log.warn("spring-auth: {} configuration warning(s), review before production:", warnings.size());
        warnings.forEach(warning -> log.warn("spring-auth:   - {}", warning));
    }
}
