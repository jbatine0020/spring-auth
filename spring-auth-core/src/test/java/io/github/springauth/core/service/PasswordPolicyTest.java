package io.github.springauth.core.service;

import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.error.AuthErrorCodes;
import io.github.springauth.core.error.PasswordException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordPolicyTest {

    private final AuthProperties.Password properties = new AuthProperties().getPassword();
    private final PasswordPolicy policy = new PasswordPolicy(properties);

    @Test
    @DisplayName("accepts a password meeting every rule")
    void validate_compliantPassword_passes() {
        assertThatCode(() -> policy.validate("Correct-Horse-42!")).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "Ab1!", "Short-1!"})
    @DisplayName("refuses anything below the minimum length")
    void validate_tooShort_refused(String password) {
        assertThatThrownBy(() -> policy.validate(password))
                .isInstanceOf(PasswordException.class)
                .extracting(thrown -> ((PasswordException) thrown).getCode())
                .isEqualTo(AuthErrorCodes.PASSWORD_TOO_SHORT);
    }

    @Test
    @DisplayName("refuses a null password")
    void validate_null_refused() {
        assertThatThrownBy(() -> policy.validate(null)).isInstanceOf(PasswordException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "correct-horse-42!",   // no uppercase
            "CORRECT-HORSE-42!",   // no lowercase
            "Correct-Horse-Ab!",   // no digit
            "CorrectHorse4242"     // no special character
    })
    @DisplayName("refuses a password missing a required character class")
    void validate_missingCharacterClass_refused(String password) {
        assertThatThrownBy(() -> policy.validate(password))
                .isInstanceOf(PasswordException.class)
                .extracting(thrown -> ((PasswordException) thrown).getCode())
                .isEqualTo(AuthErrorCodes.PASSWORD_TOO_WEAK);
    }

    @Test
    @DisplayName("honours a relaxed configuration")
    void validate_relaxedRules_accepted() {
        properties.setRequireSpecial(false);
        properties.setRequireDigit(false);
        properties.setMinLength(8);

        assertThatCode(() -> policy.validate("Passphrase")).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("describes the active rules for a form hint")
    void describe_listsTheActiveRules() {
        assertThat(policy.describe())
                .contains("12 caractères minimum")
                .contains("une majuscule")
                .contains("un chiffre")
                .contains("un caractère spécial");
    }

    @Test
    @DisplayName("a long passphrase without symbols passes once symbols are optional")
    void validate_passphrase_acceptedWhenSymbolsOptional() {
        properties.setRequireSpecial(false);

        assertThatCode(() -> policy.validate("Batterie4Cheval5Agrafe"))
                .doesNotThrowAnyException();
    }
}
