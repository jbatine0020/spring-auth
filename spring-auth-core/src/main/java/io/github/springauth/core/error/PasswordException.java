package io.github.springauth.core.error;

/**
 * Password policy, change and reset failures.
 *
 * <p>Unlike login errors these are safe to be specific: the caller is already authenticated,
 * or holds a reset link, so telling them exactly what is wrong helps without leaking anything.
 */
public class PasswordException extends AuthException {

    private PasswordException(String code, String message) {
        super(code, message);
    }

    public static PasswordException tooShort(int minLength) {
        return new PasswordException(AuthErrorCodes.PASSWORD_TOO_SHORT,
                "Le mot de passe doit contenir au moins " + minLength + " caractères");
    }

    public static PasswordException tooWeak(String requirement) {
        return new PasswordException(AuthErrorCodes.PASSWORD_TOO_WEAK,
                "Le mot de passe doit contenir " + requirement);
    }

    public static PasswordException reused(int historySize) {
        return new PasswordException(AuthErrorCodes.PASSWORD_REUSED,
                "Le nouveau mot de passe ne doit pas réutiliser l'un de vos "
                        + historySize + " derniers mots de passe");
    }

    public static PasswordException currentPasswordMismatch() {
        return new PasswordException(AuthErrorCodes.PASSWORD_MISMATCH,
                "Le mot de passe actuel est incorrect");
    }

    public static PasswordException changeNotRequired() {
        return new PasswordException(AuthErrorCodes.PASSWORD_CHANGE_NOT_REQUIRED,
                "Aucun changement obligatoire de mot de passe n’est en attente");
    }

    public static PasswordException changeRequired() {
        return new PasswordException(AuthErrorCodes.PASSWORD_CHANGE_REQUIRED,
                "Vous devez changer votre mot de passe avant de poursuivre");
    }

    public static PasswordException resetInvalid() {
        return new PasswordException(AuthErrorCodes.PASSWORD_RESET_INVALID,
                "Ce lien de réinitialisation est invalide");
    }

    public static PasswordException resetExpired() {
        return new PasswordException(AuthErrorCodes.PASSWORD_RESET_EXPIRED,
                "Ce lien de réinitialisation a expiré");
    }

    public static PasswordException resetAlreadyUsed() {
        return new PasswordException(AuthErrorCodes.PASSWORD_RESET_ALREADY_USED,
                "Ce lien de réinitialisation a déjà été utilisé");
    }

    public static PasswordException resetLocked() {
        return new PasswordException(AuthErrorCodes.PASSWORD_RESET_LOCKED,
                "Ce lien de réinitialisation a été verrouillé après trop de tentatives");
    }
}
