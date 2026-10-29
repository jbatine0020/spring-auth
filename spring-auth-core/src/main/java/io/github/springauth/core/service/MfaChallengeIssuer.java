package io.github.springauth.core.service;

import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.jwt.JwtIssuer;
import io.github.springauth.core.jwt.TokenPurpose;
import io.github.springauth.core.model.AuthUserId;

/** Shared issuer for short-lived MFA challenge tokens. */
public final class MfaChallengeIssuer {
    private final JwtIssuer jwtIssuer;
    private final AuthProperties properties;

    public MfaChallengeIssuer(JwtIssuer jwtIssuer, AuthProperties properties) {
        this.jwtIssuer = jwtIssuer;
        this.properties = properties;
    }

    public String issue(AuthUserId userId) {
        return jwtIssuer.issuePurposeToken(userId, TokenPurpose.MFA_CHALLENGE,
                properties.getMfa().getChallengeTtl()).token();
    }
    public String issueEnrollment(AuthUserId userId) {
        return jwtIssuer.issuePurposeToken(userId, TokenPurpose.MFA_ENROLLMENT,
                properties.getMfa().getEnrollmentTtl()).token();
    }
}
