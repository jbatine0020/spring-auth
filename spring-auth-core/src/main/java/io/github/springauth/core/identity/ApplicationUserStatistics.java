package io.github.springauth.core.identity;

/** Global user counters, deliberately independent from a paginated user list. */
public record ApplicationUserStatistics(
        long total,
        long active,
        long disabled,
        long locked,
        long pendingMfa) {
}
