package io.github.springauth.core.service;

import java.time.Instant;

import io.github.springauth.core.jwt.JwtIssuer;

/**
 * The credential pair handed to a client once authentication completes.
 *
 * <p>{@code refreshToken} is the only time the raw secret exists outside the client: it is not
 * recoverable afterwards, since storage keeps its digest only.
 *
 * @param accessToken      signed JWT to send as {@code Authorization: Bearer}
 * @param refreshToken     opaque secret used to obtain the next access token
 * @param tokenType        always {@code Bearer}, present for OAuth2-shaped clients
 * @param expiresInSeconds access token lifetime
 * @param expiresAt        absolute access token expiry
 */
public record AuthTokens(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresInSeconds,
        Instant expiresAt) {

    private static final String BEARER = "Bearer";

    public static AuthTokens of(JwtIssuer.IssuedToken access, String refreshToken) {
        return new AuthTokens(access.token(), refreshToken, BEARER,
                access.expiresInSeconds(), access.expiresAt());
    }
}
