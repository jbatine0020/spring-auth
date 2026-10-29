package io.github.springauth.web.controller;

import io.github.springauth.core.jwt.JwtKeyProvider;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Publishes the JSON Web Key Set at {@code /.well-known/jwks.json}.
 *
 * <p>Lets a gateway or a peer service validate the tokens this application issues without sharing
 * any secret: public keys only, which is the whole point of signing with RSA rather than a shared
 * HMAC key.
 *
 * <p>During a key rotation the set holds both the current and the previous key, so tokens minted
 * before the switch keep validating until they expire.
 */
@RestController
public class JwksController {

    private final JwtKeyProvider keyProvider;

    public JwksController(JwtKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> jwks() {
        // JWKSet.toString() emits the public parameters only; the private key never leaves the JVM.
        return ResponseEntity.ok(keyProvider.getJwkSetJson());
    }
}
