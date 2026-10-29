package io.github.springauth.core.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class OtpChallengeTest {

    @Test
    void expiresLocksAndCannotBeConsumedAgain() {
        Instant now = Instant.parse("2026-08-12T15:00:00Z");
        OtpChallenge challenge = OtpChallenge.issue(AuthUserId.of("user-1"), OtpChannel.EMAIL,
                "$2a$12$hash", "fingerprint", "j***@example.test", now, Duration.ofMinutes(5));

        assertThat(challenge.canVerifyAt(now.plusSeconds(299))).isTrue();
        challenge.recordInvalidAttempt(2, now.plusSeconds(1));
        assertThat(challenge.canVerifyAt(now.plusSeconds(2))).isTrue();
        challenge.recordInvalidAttempt(2, now.plusSeconds(3));
        assertThat(challenge.canVerifyAt(now.plusSeconds(4))).isFalse();

        OtpChallenge renewed = OtpChallenge.reissue(challenge, "$2a$12$new", "fingerprint",
                "j***@example.test", now, Duration.ofMinutes(5));
        renewed.consume(now.plusSeconds(10));
        assertThat(renewed.canVerifyAt(now.plusSeconds(11))).isFalse();
        assertThat(renewed.canVerifyAt(now.plus(Duration.ofMinutes(6)))).isFalse();
    }
}
