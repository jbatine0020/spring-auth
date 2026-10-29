package io.github.springauth.core.error;

/**
 * Authentication failed, deliberately indistinguishable across causes.
 *
 * <p>Unknown login, wrong password, disabled account, pending activation and locked account all
 * raise this exception with the same code and message. Anything finer lets an attacker probe
 * which addresses are registered. The real reason is written to the login history instead, where
 * only operators can read it.
 */
public class InvalidCredentialsException extends AuthException {

    public InvalidCredentialsException() {
        super(AuthErrorCodes.LOGIN_INVALID, "Identifiants invalides");
    }
}
