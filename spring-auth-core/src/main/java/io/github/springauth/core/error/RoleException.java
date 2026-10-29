package io.github.springauth.core.error;

/** Role administration failures raised by the RBAC module. */
public class RoleException extends AuthException {

    private RoleException(String code, String message) {
        super(code, message);
    }

    public static RoleException notFound(String code) {
        return new RoleException(AuthErrorCodes.ROLE_NOT_FOUND, "Rôle introuvable : " + code);
    }

    public static RoleException alreadyExists(String code) {
        return new RoleException(AuthErrorCodes.ROLE_ALREADY_EXISTS,
                "Un rôle portant le code " + code + " existe déjà");
    }
}
