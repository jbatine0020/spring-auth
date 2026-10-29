package io.github.springauth.core.error;

import java.time.Instant;

/**
 * Second-factor failures: missing code, wrong code, lock-out, missing enrolment, or an
 * invalid short-lived challenge token.
 *
 * <p>Static factories keep the codes in one place and make call sites read like the rule
 * they enforce.
 */
public class MfaException extends AuthException {

    private final Instant lockedUntil;

    private MfaException(String code, String message, Instant lockedUntil) {
        super(code, message);
        this.lockedUntil = lockedUntil;
    }

    /** A step-up confirmation is required but the caller sent no code. */
    public static MfaException required() {
        return new MfaException(AuthErrorCodes.MFA_REQUIRED,
                "Confirmation MFA requise : fournissez un code TOTP", null);
    }

    /** The submitted code is wrong, outside the tolerated window, or already used. */
    public static MfaException invalidCode() {
        return new MfaException(AuthErrorCodes.MFA_INVALID_CODE,
                "Code TOTP invalide ou expiré", null);
    }

    /** Too many invalid codes: verification is frozen until {@code lockedUntil}. */
    public static MfaException locked(Instant lockedUntil) {
        return new MfaException(AuthErrorCodes.MFA_LOCKED,
                "Trop de tentatives MFA. Réessayez dans quelques minutes", lockedUntil);
    }

    /** MFA is required for this user but no factor has been enrolled. */
    public static MfaException notEnrolled() {
        return new MfaException(AuthErrorCodes.MFA_NOT_ENROLLED,
                "Aucun facteur MFA enrôlé pour ce compte", null);
    }

    /** The challenge or enrolment token is malformed, expired, or has the wrong purpose. */
    public static MfaException invalidChallenge() {
        return new MfaException(AuthErrorCodes.MFA_CHALLENGE_INVALID,
                "Session d'authentification expirée, reprenez la connexion", null);
    }

    /** When the failure is a lock-out, the instant verification becomes possible again. */
    public Instant getLockedUntil() {
        return lockedUntil;
    }
}
