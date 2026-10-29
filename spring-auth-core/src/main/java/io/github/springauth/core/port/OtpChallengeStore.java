package io.github.springauth.core.port;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.OtpChallenge;
import io.github.springauth.core.model.OtpChannel;
import java.util.Optional;

/** Store with a pessimistic read for atomic OTP validation and consumption. */
public interface OtpChallengeStore {
    Optional<OtpChallenge> findForUpdate(AuthUserId userId, OtpChannel channel);
    OtpChallenge save(OtpChallenge challenge);
}
