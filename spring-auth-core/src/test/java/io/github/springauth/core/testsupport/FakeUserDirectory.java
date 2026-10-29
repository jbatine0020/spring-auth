package io.github.springauth.core.testsupport;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import io.github.springauth.core.model.AuthUser;
import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.spi.AuthUserDirectory;

/** Directory backed by a map, standing in for the host application's user table. */
public class FakeUserDirectory implements AuthUserDirectory {

    private final Map<String, AuthUser> byLogin = new LinkedHashMap<>();
    private final Map<String, AuthUser> byId = new LinkedHashMap<>();

    public FakeUserDirectory add(AuthUser user) {
        byLogin.put(user.login().toLowerCase(), user);
        byId.put(user.id().value(), user);
        return this;
    }

    /** Replaces a user, for tests that change a status mid-flow. */
    public FakeUserDirectory replace(AuthUser user) {
        return add(user);
    }

    @Override
    public Optional<AuthUser> findByLogin(String login) {
        return login == null ? Optional.empty()
                : Optional.ofNullable(byLogin.get(login.trim().toLowerCase()));
    }

    @Override
    public Optional<AuthUser> findById(AuthUserId id) {
        return Optional.ofNullable(byId.get(id.value()));
    }
}
