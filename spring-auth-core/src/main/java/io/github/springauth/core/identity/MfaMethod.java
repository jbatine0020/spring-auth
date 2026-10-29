package io.github.springauth.core.identity;

/** MFA method configured for an application user. Values are part of the public JSON contract. */
public enum MfaMethod {
    NONE,
    TOTP,
    EMAIL_OTP,
    SMS_OTP;

    public static MfaMethod parse(String value) {
        if (value == null || value.isBlank()) return NONE;
        try {
            return value.trim().toUpperCase(java.util.Locale.ROOT).equals("OTP")
                    ? EMAIL_OTP : valueOf(value.trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Unsupported MFA method: " + value, ex);
        }
    }
}
