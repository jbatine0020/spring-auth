package io.github.springauth.core.port;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

class WebAuthnCounterContractTest {
    @Test
    void acceptsOnlyStrictlyIncreasingCounters() {
        AtomicLong stored = new AtomicLong(4);
        WebAuthnCredentialStore store = new WebAuthnCredentialStore() {
            public java.util.List<io.github.springauth.core.model.WebAuthnCredential> findByUserId(io.github.springauth.core.model.AuthUserId id) { return java.util.List.of(); }
            public java.util.Optional<io.github.springauth.core.model.WebAuthnCredential> findByCredentialId(String id) { return java.util.Optional.empty(); }
            public io.github.springauth.core.model.WebAuthnCredential save(io.github.springauth.core.model.WebAuthnCredential c) { return c; }
            public boolean acceptSignatureCounter(String id, long value) {
                while (true) {
                    long current = stored.get();
                    if (value <= current || !stored.compareAndSet(current, value)) {
                        if (value <= current) return false;
                        continue;
                    }
                    return true;
                }
            }
            public void deleteByCredentialId(String id) {}
        };
        assertThat(store.acceptSignatureCounter("c", 5)).isTrue();
        assertThat(store.acceptSignatureCounter("c", 5)).isFalse();
    }
}
