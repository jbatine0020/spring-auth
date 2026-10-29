package io.github.springauth.core.identity;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class ExternalAuthenticationServiceTest {
    @Test void unknownLocalUserIsRejectedBeforeDirectoryCall() {
        AtomicInteger calls=new AtomicInteger();
        IdentityProvider provider=provider(calls);
        var service=new ExternalAuthenticationService(provider,new IdentityMirrorService(new MirrorStore(),Clock.systemUTC()),new UserStore(null));
        assertThatThrownBy(() -> service.authenticate("unknown", "secret".toCharArray()))
                .isInstanceOf(IdentityProviderException.class);
        assertThat(calls).hasValue(0);
    }

    @Test void activeAuthorizedUserIsValidatedByDirectoryOnce() throws Exception {
        AtomicInteger calls=new AtomicInteger(); Instant now=Instant.now();
        var user=new ApplicationUser(UUID.randomUUID(),"john.doe","john@example.test",null,"John Doe","john.doe","ACTIVE","NONE",Set.of("USER"),now,now);
        var mirrors = new MirrorStore();
        mirrors.save(new IdentityUserMirror(UUID.randomUUID(), "test", "john.doe", "john.doe",
                "John Doe", "john@example.test", "ACTIVE", false, Set.of(), now, now));
        var service=new ExternalAuthenticationService(provider(calls),new IdentityMirrorService(mirrors,Clock.systemUTC()),new UserStore(user));
        service.authenticate("john.doe","password".toCharArray());
        assertThat(calls).hasValue(1);
    }
    private IdentityProvider provider(AtomicInteger calls) { return new IdentityProvider() {
        public String providerId(){return "test";}
        public IdentityAuthenticationResult authenticate(String login,char[] password){calls.incrementAndGet();return new IdentityAuthenticationResult("john.doe","john.doe","John Doe","john@example.test",Map.of());}
    };}
    private static class UserStore implements ApplicationUserStore { private final ApplicationUser user; UserStore(ApplicationUser u){user=u;} public Optional<ApplicationUser> findByLogin(String l){return Optional.ofNullable(user).filter(u->u.login().equals(l));} public Optional<ApplicationUser> findByExternalSubject(String s){return Optional.ofNullable(user).filter(u->u.externalSubject().equals(s));} public Optional<ApplicationUser> findById(UUID id){return Optional.ofNullable(user).filter(u->u.id().equals(id));} public java.util.List<ApplicationUser> findAll(){return user==null?java.util.List.of():java.util.List.of(user);} public ApplicationUser save(ApplicationUser u){return u;} }
    private static class MirrorStore implements IdentityMirrorStore { private IdentityUserMirror value; public Optional<IdentityUserMirror> find(String p,String s){return Optional.ofNullable(value);} public Optional<IdentityUserMirror> findByLogin(String l){return Optional.ofNullable(value);} public Optional<IdentityUserMirror> findById(UUID id){return Optional.ofNullable(value);} public IdentityUserMirror save(IdentityUserMirror m){value=m;return m;} }
}
