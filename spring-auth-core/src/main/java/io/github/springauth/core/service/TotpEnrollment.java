package io.github.springauth.core.service;

/**
 * Everything a client needs to display an enrolment screen.
 *
 * <p>The secret is returned in clear <b>once</b>, at enrolment time, because the user has to copy
 * it into their authenticator. It is never retrievable afterwards: storage keeps it encrypted and
 * no endpoint reads it back. Render the QR code from {@code otpauthUri} and offer
 * {@code base32Secret} as the manual fallback.
 *
 * @param base32Secret shared secret, base32-encoded
 * @param otpauthUri   {@code otpauth://totp/...} URI to encode as a QR code
 * @param issuer       label shown in the authenticator app
 * @param account      account label shown under the issuer
 */
public record TotpEnrollment(String base32Secret, String otpauthUri, String issuer, String account) {}
