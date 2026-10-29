package io.github.springauth.core.service;

import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.error.PasswordException;

/**
 * Complexity rules applied to every new password.
 *
 * <p>Length carries most of the strength, which is why the default minimum is twelve rather than
 * the customary eight; the character-class requirements are configurable because some
 * organisations mandate them and others deliberately drop them in favour of longer passphrases.
 *
 * <p>Validation happens before hashing, on the raw value. Nothing here is logged.
 */
public class PasswordPolicy {

    private final AuthProperties.Password properties;

    public PasswordPolicy(AuthProperties.Password properties) {
        this.properties = properties;
    }

    /**
     * @throws PasswordException with {@code PASSWORD_TOO_SHORT} or {@code PASSWORD_TOO_WEAK}
     */
    public void validate(String password) {
        if (password == null || password.length() < properties.getMinLength()) {
            throw PasswordException.tooShort(properties.getMinLength());
        }
        if (properties.isRequireUppercase() && password.chars().noneMatch(Character::isUpperCase)) {
            throw PasswordException.tooWeak("au moins une majuscule");
        }
        if (properties.isRequireLowercase() && password.chars().noneMatch(Character::isLowerCase)) {
            throw PasswordException.tooWeak("au moins une minuscule");
        }
        if (properties.isRequireDigit() && password.chars().noneMatch(Character::isDigit)) {
            throw PasswordException.tooWeak("au moins un chiffre");
        }
        if (properties.isRequireSpecial()
                && password.chars().noneMatch(c -> !Character.isLetterOrDigit(c))) {
            throw PasswordException.tooWeak("au moins un caractère spécial");
        }
    }

    /** Human-readable summary, handy for a registration form hint. */
    public String describe() {
        StringBuilder description = new StringBuilder()
                .append(properties.getMinLength()).append(" caractères minimum");
        if (properties.isRequireUppercase()) {
            description.append(", une majuscule");
        }
        if (properties.isRequireLowercase()) {
            description.append(", une minuscule");
        }
        if (properties.isRequireDigit()) {
            description.append(", un chiffre");
        }
        if (properties.isRequireSpecial()) {
            description.append(", un caractère spécial");
        }
        return description.toString();
    }
}
