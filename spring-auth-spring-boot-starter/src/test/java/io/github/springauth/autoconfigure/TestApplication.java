package io.github.springauth.autoconfigure;

import java.util.Optional;
import java.util.Set;

import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.AuthUserStatus;
import io.github.springauth.core.model.MfaRequirement;
import io.github.springauth.core.spi.AuthUserDirectory;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * Minimal host application, standing in for a real consumer.
 *
 * <p>It supplies exactly what the library demands of an application, an
 * {@link AuthUserDirectory}, and nothing else, which is what makes the test meaningful: it proves
 * a project can adopt the starter by writing one class.
 */
@SpringBootApplication
public class TestApplication {

    /** Two fixed users: one without a second factor, one with. */
    @Bean
    AuthUserDirectory testUserDirectory() {
        AuthUser plain = AuthUser.builder(AuthUserId.of("11111111-1111-1111-1111-111111111111"),
                        "alex@example.com")
                .email("alex@example.com")
                .status(AuthUserStatus.ACTIVE)
                .roleCodes(Set.of("ADMIN"))
                .build();
        AuthUser withMfa = AuthUser.builder(AuthUserId.of("22222222-2222-2222-2222-222222222222"),
                        "mfa@example.com")
                .email("mfa@example.com")
                .status(AuthUserStatus.ACTIVE)
                .mfaRequirement(MfaRequirement.REQUIRED)
                .build();

        return new AuthUserDirectory() {

            @Override
            public Optional<AuthUser> findByLogin(String login) {
                if (plain.login().equalsIgnoreCase(login)) {
                    return Optional.of(plain);
                }
                return withMfa.login().equalsIgnoreCase(login) ? Optional.of(withMfa) : Optional.empty();
            }

            @Override
            public Optional<AuthUser> findById(AuthUserId id) {
                if (plain.id().equals(id)) {
                    return Optional.of(plain);
                }
                return withMfa.id().equals(id) ? Optional.of(withMfa) : Optional.empty();
            }
        };
    }
}
