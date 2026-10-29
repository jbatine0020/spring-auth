package io.github.springauth.core.service;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.crypto.SecretCipher;
import io.github.springauth.core.crypto.TotpGenerator;
import io.github.springauth.core.error.AuthException;
import io.github.springauth.core.error.MfaException;
import io.github.springauth.core.jwt.PurposeTokenVerifier;
import io.github.springauth.core.jwt.TokenPurpose;
import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.LockoutPolicy;
import io.github.springauth.core.model.MfaCredential;
import io.github.springauth.core.model.MfaStatus;
import io.github.springauth.core.model.RequestContext;
import io.github.springauth.core.port.MfaCredentialStore;
import io.github.springauth.core.spi.AuthUserDirectory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.annotation.Transactional;

/**
 * Enrolment, verification and reset of the TOTP second factor.
 *
 * <h2>Enrolment is two-phase on purpose</h2>
 * <p>{@link #startEnrollment} stores a seed but leaves the factor unconfirmed;
 * {@link #confirmEnrollment} validates a first code and only then does the factor count. Without
 * that second phase, a user who scanned a QR code into the wrong app, or never scanned it at all,
 * would be locked out of their own account at the next login.
 *
 * <h2>What stops code guessing</h2>
 * <p>Six digits is a million combinations, and the holder of a challenge token can try them from
 * anywhere. Two things bound that: a per-account lock-out after a handful of wrong codes,
 * independent of the source address, and the replay counter that prevents a code observed once
 * from being reused inside its own thirty-second step.
 *
 * <p>{@code noRollbackFor = AuthException.class} keeps the failure counter committed when
 * verification throws, otherwise the lock-out would never accumulate.
 */
@Transactional(noRollbackFor = AuthException.class)
public class MfaService {

    private static final Logger log = LoggerFactory.getLogger(MfaService.class);

    private final MfaCredentialStore mfaCredentialStore;
    private final AuthUserDirectory userDirectory;
    private final PurposeTokenVerifier purposeTokenVerifier;
    private final TotpGenerator totpGenerator;
    private final SecretCipher secretCipher;
    private final SessionService sessionService;
    private final AuthAuditor auditor;
    private final AuthProperties properties;
    private final Clock clock;

    public MfaService(MfaCredentialStore mfaCredentialStore,
                      AuthUserDirectory userDirectory,
                      PurposeTokenVerifier purposeTokenVerifier,
                      TotpGenerator totpGenerator,
                      SecretCipher secretCipher,
                      SessionService sessionService,
                      AuthAuditor auditor,
                      AuthProperties properties,
                      Clock clock) {
        this.mfaCredentialStore = mfaCredentialStore;
        this.userDirectory = userDirectory;
        this.purposeTokenVerifier = purposeTokenVerifier;
        this.totpGenerator = totpGenerator;
        this.secretCipher = secretCipher;
        this.sessionService = sessionService;
        this.auditor = auditor;
        this.properties = properties;
        this.clock = clock;
    }

    /**
     * Generates a factor for a user who has just cleared the password step and holds an enrolment
     * token.
     *
     * <p>Calling it twice simply replaces the previous unconfirmed seed, which is what makes
     * "restart the enrolment" work when a user abandons the flow.
     *
     * @throws MfaException {@code MFA_CHALLENGE_INVALID} when the token is invalid or expired
     */
    public TotpEnrollment startEnrollment(String enrollmentToken) {
        AuthUser user = requireUserFrom(enrollmentToken, TokenPurpose.MFA_ENROLLMENT);
        return startEnrollmentFor(user);
    }

    /**
     * Same as {@link #startEnrollment}, for a user who is already authenticated and re-enrolling
     * from their security settings.
     */
    public TotpEnrollment startEnrollmentFor(AuthUser user) {
        Instant now = clock.instant();
        String base32Secret = totpGenerator.generateBase32Secret();
        String encrypted = secretCipher.encrypt(base32Secret);

        MfaCredential credential = mfaCredentialStore.findByUserId(user.id())
                .map(existing -> {
                    existing.replaceSecret(encrypted, now);
                    return existing;
                })
                .orElseGet(() -> MfaCredential.enroll(user.id(), encrypted, now));
        mfaCredentialStore.save(credential);

        String account = user.email() != null && !user.email().isBlank() ? user.email() : user.login();
        String issuer = properties.getMfa().getIssuerLabel();
        return new TotpEnrollment(base32Secret,
                totpGenerator.buildOtpauthUri(issuer, account, base32Secret), issuer, account);
    }

    /**
     * Validates the first code of an enrolment and opens a session.
     *
     * @throws MfaException on an invalid token, a wrong code, or a locked factor
     */
    public AuthTokens confirmEnrollment(String enrollmentToken, String code) {
        return confirmEnrollment(enrollmentToken, code, RequestContext.empty());
    }

    /** Confirms an enrolment and records the resulting authenticated session context. */
    public AuthTokens confirmEnrollment(String enrollmentToken, String code, RequestContext context) {
        AuthUser user = requireUserFrom(enrollmentToken, TokenPurpose.MFA_ENROLLMENT);
        return confirmEnrollmentFor(user, code, context);
    }

    /** Confirms an enrolment started from an already authenticated server session. */
    public AuthTokens confirmEnrollmentFor(AuthUser user, String code) {
        return confirmEnrollmentFor(user, code, RequestContext.empty());
    }

    /** Confirms an enrolment started from an already authenticated server session. */
    public AuthTokens confirmEnrollmentFor(AuthUser user, String code, RequestContext context) {
        verifyCodeOrThrow(user, code, context);
        auditor.mfaEnrolled(user, clock.instant());
        return sessionService.openSession(user, context);
    }

    /**
     * Completes a login for a user who already owns a confirmed factor.
     *
     * @throws MfaException on an invalid challenge token, a wrong code, or a locked factor
     */
    public AuthTokens verifyForLogin(String challengeToken, String code, RequestContext context) {
        AuthUser user = requireUserFrom(challengeToken, TokenPurpose.MFA_CHALLENGE);
        verifyCodeOrThrow(user, code, context);
        return sessionService.openSession(user, context);
    }

    /**
     * Confirms a sensitive action for an already-authenticated user (step-up).
     *
     * <p>The code is consumed: one action, one code. Replaying the same code for a second action
     * inside the same time step is refused by the counter guard.
     *
     * @throws MfaException {@code MFA_REQUIRED} when no code was supplied
     */
    public void verifyStepUp(AuthUserId userId, String code) {
        verifyStepUp(userId, code, "legacy");
    }

    /** Verifies a step-up code bound to one canonical action fingerprint. */
    public void verifyStepUp(AuthUserId userId, String code, String actionDigest) {
        if (code == null || code.isBlank()) {
            throw MfaException.required();
        }
        if (actionDigest == null || actionDigest.isBlank()) {
            throw MfaException.required();
        }
        AuthUser user = userDirectory.findById(userId).orElseThrow(MfaException::invalidChallenge);
        verifyCodeOrThrow(user, code, RequestContext.empty());
    }

    /**
     * Administrative reset: the seed is rotated and left unconfirmed, so the user enrols again at
     * their next login.
     *
     * @param performedBy identifier of the administrator, for the audit trail
     */
    public void resetFor(AuthUserId userId, String performedBy) {
        Instant now = clock.instant();
        AuthUser user = userDirectory.findById(userId).orElseThrow(MfaException::invalidChallenge);
        String placeholderSecret = secretCipher.encrypt(totpGenerator.generateBase32Secret());
        MfaCredential credential = mfaCredentialStore.findByUserId(userId)
                .map(existing -> {
                    existing.rotateSecret(placeholderSecret, now);
                    return existing;
                })
                .orElseGet(() -> {
                    MfaCredential fresh = MfaCredential.enroll(userId, placeholderSecret, now);
                    fresh.rotateSecret(placeholderSecret, now);
                    return fresh;
                });
        mfaCredentialStore.save(credential);
        // Outstanding sessions were opened with the old factor: close them.
        sessionService.revokeAllSessions(userId);
        auditor.mfaReset(user, performedBy, now);
        log.info("spring-auth: MFA factor reset for userId={} by {}", userId.value(), performedBy);
    }

    /** Removes the factor entirely. Used when deleting a user. */
    public void deleteFor(AuthUserId userId) {
        mfaCredentialStore.deleteByUserId(userId);
    }

    @Transactional(readOnly = true)
    public MfaStatus statusOf(AuthUser user) {
        if (!user.requiresMfa()) {
            return MfaStatus.NOT_APPLICABLE;
        }
        return mfaCredentialStore.findByUserId(user.id())
                .map(MfaCredential::status)
                .orElse(MfaStatus.NOT_CONFIGURED);
    }

    /**
     * The shared verification path: lock-out check, code validation, counter advance, and
     * persistence of the outcome either way.
     */
    private void verifyCodeOrThrow(AuthUser user, String code, RequestContext context) {
        Instant now = clock.instant();
        MfaCredential credential = mfaCredentialStore.findByUserIdForUpdate(user.id())
                .orElseThrow(MfaException::notEnrolled);

        if (credential.isLockedAt(now)) {
            throw MfaException.locked(credential.getLockedUntil());
        }

        String secret = secretCipher.decrypt(credential.getEncryptedSecret());
        AuthProperties.Mfa mfa = properties.getMfa();
        Optional<Long> counter = totpGenerator.verifyCode(secret, code,
                credential.getLastAcceptedCounter(), now, mfa.getDigits(), mfa.getWindow());

        if (counter.isEmpty()) {
            boolean justLocked = credential.recordFailedAttempt(
                    new LockoutPolicy(mfa.getMaxFailedAttempts(), mfa.getLockoutDuration()), now);
            mfaCredentialStore.save(credential);
            auditor.mfaVerificationFailed(user, context, now);
            if (justLocked) {
                throw MfaException.locked(credential.getLockedUntil());
            }
            throw MfaException.invalidCode();
        }

        credential.recordSuccessfulVerification(counter.get(), now);
        mfaCredentialStore.save(credential);
    }

    private AuthUser requireUserFrom(String token, TokenPurpose purpose) {
        AuthUserId userId = purposeTokenVerifier.verify(token, purpose)
                .orElseThrow(MfaException::invalidChallenge);
        AuthUser user = userDirectory.findById(userId).orElseThrow(MfaException::invalidChallenge);
        if (!user.canAuthenticate()) {
            // The account changed state between the password step and this one.
            throw MfaException.invalidChallenge();
        }
        return user;
    }
}
