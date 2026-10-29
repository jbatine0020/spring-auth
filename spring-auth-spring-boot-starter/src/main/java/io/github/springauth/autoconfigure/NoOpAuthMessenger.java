package io.github.springauth.autoconfigure;

import io.github.springauth.core.spi.AuthMessenger;

/**
 * Fallback messenger that delivers nothing.
 *
 * <p>Registered only when the application supplies none, so the context still starts. Its presence
 * is what the startup report keys on to warn that reset codes and invitation links are being
 * generated and thrown away.
 */
public class NoOpAuthMessenger implements AuthMessenger {
    // every method of the interface defaults to no-op
}
