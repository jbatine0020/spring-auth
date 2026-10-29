package io.github.springauth.core.model;

/**
 * Whether a second factor applies to a given user.
 *
 * <p>Decided by the host application (through {@link io.github.springauth.core.spi.AuthUserDirectory}),
 * because the rule is usually a business one: internal staff authenticating against a corporate
 * directory may be exempt while external customers are not.
 */
public enum MfaRequirement {

    /** No second factor for this user. Login issues tokens right after the password check. */
    NOT_APPLICABLE,

    /** A TOTP factor is mandatory: the user enrols one on first login, then verifies at each login. */
    REQUIRED
}
