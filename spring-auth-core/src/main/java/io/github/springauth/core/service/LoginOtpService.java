package io.github.springauth.core.service;

import io.github.springauth.core.config.AuthProperties;
import io.github.springauth.core.crypto.NumericOtpFactory;
import io.github.springauth.core.jwt.JwtIssuer;
import io.github.springauth.core.jwt.PurposeTokenVerifier;
import io.github.springauth.core.jwt.TokenPurpose;
import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.OtpChallenge;
import io.github.springauth.core.error.OtpResendCooldownException;
import io.github.springauth.core.model.OtpChannel;
import io.github.springauth.core.model.RequestContext;
import io.github.springauth.core.port.OtpChallengeStore;
import io.github.springauth.core.spi.AuthMessenger;
import io.github.springauth.core.spi.AuthUserDirectory;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import org.springframework.transaction.annotation.Transactional;

/** Issues and atomically consumes e-mail/SMS login codes. */
// Invalid codes update the attempt counter before throwing; that state must commit.
@Transactional(noRollbackFor = IllegalArgumentException.class)
public class LoginOtpService {

    private final OtpChallengeStore challenges;
    private final NumericOtpFactory otpFactory;
    private final JwtIssuer jwtIssuer;
    private final PurposeTokenVerifier purposeTokens;
    private final AuthMessenger messenger;
    private final AuthUserDirectory users;
    private final SessionService sessions;
    private final AuthProperties properties;
    private final Clock clock;

    public LoginOtpService(OtpChallengeStore challenges, NumericOtpFactory otpFactory, JwtIssuer jwtIssuer,
                           PurposeTokenVerifier purposeTokens, AuthMessenger messenger,
                           AuthUserDirectory users, SessionService sessions,
                           AuthProperties properties, Clock clock) {
        this.challenges = challenges;
        this.otpFactory = otpFactory;
        this.jwtIssuer = jwtIssuer;
        this.purposeTokens = purposeTokens;
        this.messenger = messenger;
        this.users = users;
        this.sessions = sessions;
        this.properties = properties;
        this.clock = clock;
    }

    public IssuedChallenge issue(AuthUser user, OtpChannel channel) {
        return issue(user, channel, false);
    }

    public IssuedChallenge resend(String challengeToken) {
        AuthUserId userId = purposeTokens.verify(challengeToken, TokenPurpose.LOGIN_OTP)
                .orElseThrow(() -> new IllegalArgumentException("Invalid OTP challenge"));
        AuthUser user = users.findById(userId).orElseThrow(() -> new IllegalArgumentException("Unknown user"));
        return issue(user, channelFor(user), true);
    }

    private IssuedChallenge issue(AuthUser user, OtpChannel channel, boolean enforceCooldown) {
        String destination = destination(user, channel);
        Instant now = clock.instant();
        var issued = otpFactory.issue();
        var previous = challenges.findForUpdate(user.id(), channel);
        if (enforceCooldown && previous.isPresent()
                && !previous.get().canResendAt(now, properties.getOtp().getResendCooldown())) {
            Instant retryAt = previous.get().lastSentAt().plus(properties.getOtp().getResendCooldown());
            long retryAfterSeconds = Math.max(1, java.time.Duration.between(now, retryAt).toSeconds() + 1);
            throw new OtpResendCooldownException(retryAfterSeconds);
        }
        // A single locked row is renewed, making every prior code unusable atomically.
        var challenge = previous.map(value -> OtpChallenge.reissue(value, issued.hash(), fingerprint(destination),
                        mask(destination, channel), now, properties.getOtp().getTtl()))
                .orElseGet(() -> OtpChallenge.issue(user.id(), channel, issued.hash(), fingerprint(destination),
                        mask(destination, channel), now, properties.getOtp().getTtl()));
        challenges.save(challenge);
        String token = jwtIssuer.issuePurposeToken(user.id(), TokenPurpose.LOGIN_OTP,
                properties.getOtp().getTtl()).token();
        messenger.sendLoginOtp(user, channel, issued.rawCode(), challenge.expiresAt());
        return new IssuedChallenge(token, channel, challenge.destinationMasked(),
                properties.getOtp().getTtl().toSeconds(), properties.getOtp().getResendCooldown().toSeconds());
    }

    public AuthTokens verify(String challengeToken, String rawCode) {
        return verify(challengeToken, rawCode, RequestContext.empty());
    }

    public AuthTokens verify(String challengeToken, String rawCode, RequestContext context) {
        AuthUserId userId = purposeTokens.verify(challengeToken, TokenPurpose.LOGIN_OTP)
                .orElseThrow(() -> new IllegalArgumentException("Invalid OTP challenge"));
        AuthUser user = users.findById(userId).orElseThrow(() -> new IllegalArgumentException("Unknown user"));
        OtpChannel channel = channelFor(user);
        OtpChallenge challenge = challenges.findForUpdate(userId, channel)
                .orElseThrow(() -> new IllegalArgumentException("OTP challenge is invalid"));
        Instant now = clock.instant();
        if (!challenge.canVerifyAt(now) || !otpFactory.matches(rawCode, challenge.codeHash())) {
            if (challenge.canVerifyAt(now)) {
                challenge.recordInvalidAttempt(properties.getOtp().getMaxAttempts(), now);
                challenges.save(challenge);
            }
            throw new IllegalArgumentException("OTP challenge is invalid");
        }
        challenge.consume(now);
        challenges.save(challenge);
        return sessions.openSession(user, context);
    }

    private static OtpChannel channelFor(AuthUser user) {
        Object method = user.extraClaims().get("mfaMethod");
        return "SMS_OTP".equals(method) ? OtpChannel.SMS : OtpChannel.EMAIL;
    }

    private static String destination(AuthUser user, OtpChannel channel) {
        String value = channel == OtpChannel.EMAIL ? user.email() : user.phoneNumber();
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("No verified " + channel.name().toLowerCase() + " destination is available");
        }
        return value;
    }

    private static String mask(String value, OtpChannel channel) {
        if (channel == OtpChannel.EMAIL) {
            int at = value.indexOf('@');
            return at <= 1 ? "***" + value.substring(Math.max(at, 0))
                    : value.substring(0, 1) + "***" + value.substring(at);
        }
        return value.length() <= 4 ? "***" : value.substring(0, Math.min(4, value.length() - 2))
                + "*******" + value.substring(value.length() - 2);
    }

    private static String fingerprint(String value) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    public record IssuedChallenge(String challengeToken, OtpChannel channel, String destinationMasked,
                                  long expiresInSeconds, long resendAfterSeconds) { }
}
