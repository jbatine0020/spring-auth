package io.github.springauth.core.port;

import io.github.springauth.core.model.AuthUserId;

/** Provider boundary for WebAuthn ceremonies; concrete CBOR/crypto stays outside the domain. */
public interface WebAuthnProvider {

    RegistrationChallenge beginRegistration(AuthUserId userId, String displayName);

    AssertionChallenge beginAssertion(AuthUserId userId);

    WebAuthnVerification verifyRegistration(RegistrationChallenge challenge, byte[] response);

    WebAuthnVerification verifyAssertion(AssertionChallenge challenge, byte[] response);

    record RegistrationChallenge(String challengeId, AuthUserId userId, byte[] options) {}

    record AssertionChallenge(String challengeId, AuthUserId userId, byte[] options) {}

    record WebAuthnVerification(String credentialId, byte[] publicKey, long signatureCounter) {}
}
