package io.github.springauth.core.identity;

/** External identity provider used to authenticate a human account. */
public interface IdentityProvider {

    String providerId();

    IdentityAuthenticationResult authenticate(String login, char[] password)
            throws IdentityProviderException;
}
