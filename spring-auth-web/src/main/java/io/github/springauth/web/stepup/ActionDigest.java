package io.github.springauth.web.stepup;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import jakarta.servlet.http.HttpServletRequest;

/** Canonical, non-secret fingerprint of the protected HTTP action. */
public final class ActionDigest {

    private ActionDigest() {
    }

    public static String forRequest(HttpServletRequest request) {
        String canonical = request.getMethod() + "\n" + request.getRequestURI();
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(canonical.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(digest.length * 2);
            for (byte value : digest) result.append(String.format("%02x", value));
            return result.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }
}
