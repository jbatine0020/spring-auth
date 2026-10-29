package io.github.springauth.core.crypto;

import java.security.SecureRandom;

import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Generates and checks the short numeric codes sent over SMS during a password reset.
 *
 * <p>Six digits is only twenty bits of entropy, so the code alone is never the credential: it is
 * the second factor behind an emailed link, it expires quickly, and the reset request locks after
 * a handful of wrong attempts. Because the search space is small, the code is stored through the
 * application {@link PasswordEncoder} (BCrypt by default) rather than a bare digest, which makes
 * an offline sweep of a leaked table expensive.
 */
public class NumericOtpFactory {

    private final SecureRandom random = new SecureRandom();
    private final PasswordEncoder passwordEncoder;
    private final int digits;

    public NumericOtpFactory(PasswordEncoder passwordEncoder, int digits) {
        if (digits < 4 || digits > 10) {
            throw new IllegalArgumentException("OTP length must be between 4 and 10 digits, got " + digits);
        }
        this.passwordEncoder = passwordEncoder;
        this.digits = digits;
    }

    /** Draws a code and returns it alongside the hash to persist. */
    public IssuedOtp issue() {
        int bound = (int) Math.pow(10, digits);
        String rawCode = String.format("%0" + digits + "d", random.nextInt(bound));
        return new IssuedOtp(rawCode, passwordEncoder.encode(rawCode));
    }

    public boolean matches(String rawCode, String hash) {
        return rawCode != null && !rawCode.isBlank() && hash != null
                && passwordEncoder.matches(rawCode, hash);
    }

    /**
     * @param rawCode code to deliver to the user: never log it, never store it
     * @param hash    value to persist
     */
    public record IssuedOtp(String rawCode, String hash) {}
}
