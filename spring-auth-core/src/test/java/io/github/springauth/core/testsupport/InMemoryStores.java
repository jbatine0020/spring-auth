package io.github.springauth.core.testsupport;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import io.github.springauth.core.model.AuthUserId;
import io.github.springauth.core.model.Credentials;
import io.github.springauth.core.model.LoginAttempt;
import io.github.springauth.core.model.MfaCredential;
import io.github.springauth.core.model.PasswordResetRequest;
import io.github.springauth.core.model.RefreshToken;
import io.github.springauth.core.model.Role;
import io.github.springauth.core.model.UserInvitation;
import io.github.springauth.core.port.CredentialsStore;
import io.github.springauth.core.port.InvitationStore;
import io.github.springauth.core.port.LoginHistoryStore;
import io.github.springauth.core.port.MfaCredentialStore;
import io.github.springauth.core.port.PasswordHistoryStore;
import io.github.springauth.core.port.PasswordResetStore;
import io.github.springauth.core.port.RefreshTokenStore;
import io.github.springauth.core.port.RoleStore;

/**
 * In-memory implementations of every storage port, for service tests.
 *
 * <p>They behave like the JPA adapters on the points the services actually depend on, in
 * particular {@link RefreshTokens#findByTokenHash} returns revoked rows, without which replay
 * detection could not be tested at all.
 */
public final class InMemoryStores {

    private InMemoryStores() {
        // container of nested fakes
    }

    public static final class Credentials implements CredentialsStore {

        private final Map<String, io.github.springauth.core.model.Credentials> byUser =
                new ConcurrentHashMap<>();

        @Override
        public Optional<io.github.springauth.core.model.Credentials> findByUserId(AuthUserId userId) {
            return Optional.ofNullable(byUser.get(userId.value()));
        }

        @Override
        public io.github.springauth.core.model.Credentials save(
                io.github.springauth.core.model.Credentials credentials) {
            byUser.put(credentials.getUserId().value(), credentials);
            return credentials;
        }

        @Override
        public void deleteByUserId(AuthUserId userId) {
            byUser.remove(userId.value());
        }
    }

    public static final class PasswordHistory implements PasswordHistoryStore {

        private final Map<String, List<String>> byUser = new ConcurrentHashMap<>();

        @Override
        public List<String> findRecentHashes(AuthUserId userId, int limit) {
            List<String> hashes = byUser.getOrDefault(userId.value(), List.of());
            return hashes.stream().limit(limit).toList();
        }

        @Override
        public void append(AuthUserId userId, String passwordHash, Instant setAt) {
            byUser.computeIfAbsent(userId.value(), key -> new ArrayList<>()).add(0, passwordHash);
        }

        @Override
        public void deleteByUserId(AuthUserId userId) {
            byUser.remove(userId.value());
        }
    }

    public static final class MfaCredentials implements MfaCredentialStore {

        @Override
        public Optional<MfaCredential> findByUserIdForUpdate(AuthUserId userId) {
            // This fixture is used only by single-threaded domain tests.
            return findByUserId(userId);
        }

        private final Map<String, MfaCredential> byUser = new ConcurrentHashMap<>();

        @Override
        public Optional<MfaCredential> findByUserId(AuthUserId userId) {
            return Optional.ofNullable(byUser.get(userId.value()));
        }

        @Override
        public MfaCredential save(MfaCredential credential) {
            byUser.put(credential.getUserId().value(), credential);
            return credential;
        }

        @Override
        public void deleteByUserId(AuthUserId userId) {
            byUser.remove(userId.value());
        }
    }

    public static final class RefreshTokens implements RefreshTokenStore {

        @Override
        public Optional<RefreshToken> findByTokenHashForUpdate(String tokenHash) {
            // This fixture is used only by single-threaded domain tests.
            return findByTokenHash(tokenHash);
        }

        private final Map<UUID, RefreshToken> byId = new LinkedHashMap<>();

        @Override
        public Optional<RefreshToken> findByTokenHash(String tokenHash) {
            // Revoked and expired rows included on purpose: replay detection depends on it.
            return byId.values().stream()
                    .filter(token -> token.getTokenHash().equals(tokenHash))
                    .findFirst();
        }

        @Override
        public RefreshToken save(RefreshToken token) {
            byId.put(token.getId(), token);
            return token;
        }

        @Override
        public int revokeFamily(UUID familyId, Instant at) {
            int revoked = 0;
            for (RefreshToken token : byId.values()) {
                if (token.getFamilyId().equals(familyId) && !token.isRevoked()) {
                    token.revoke(at);
                    revoked++;
                }
            }
            return revoked;
        }

        @Override
        public int revokeAllForUser(AuthUserId userId, Instant at) {
            int revoked = 0;
            for (RefreshToken token : byId.values()) {
                if (token.getUserId().equals(userId) && !token.isRevoked()) {
                    token.revoke(at);
                    revoked++;
                }
            }
            return revoked;
        }

        @Override
        public int deleteExpiredBefore(Instant before) {
            int size = byId.size();
            byId.values().removeIf(token -> token.getExpiresAt().isBefore(before));
            return size - byId.size();
        }

        public int size() {
            return byId.size();
        }

        public List<RefreshToken> all() {
            return List.copyOf(byId.values());
        }
    }

    public static final class PasswordResets implements PasswordResetStore {

        private final Map<UUID, PasswordResetRequest> byId = new LinkedHashMap<>();

        @Override
        public Optional<PasswordResetRequest> findByTokenHash(String tokenHash) {
            return byId.values().stream()
                    .filter(request -> request.getTokenHash().equals(tokenHash))
                    .findFirst();
        }

        @Override
        public PasswordResetRequest save(PasswordResetRequest request) {
            byId.put(request.getId(), request);
            return request;
        }

        @Override
        public void deleteByUserId(AuthUserId userId) {
            byId.values().removeIf(request -> request.getUserId().equals(userId));
        }

        @Override
        public int deleteExpiredBefore(Instant before) {
            int size = byId.size();
            byId.values().removeIf(request -> request.getExpiresAt().isBefore(before));
            return size - byId.size();
        }

        public int size() {
            return byId.size();
        }
    }

    public static final class Invitations implements InvitationStore {

        private final Map<UUID, UserInvitation> byId = new LinkedHashMap<>();

        @Override
        public Optional<UserInvitation> findByTokenHash(String tokenHash) {
            return byId.values().stream()
                    .filter(invitation -> invitation.getTokenHash().equals(tokenHash))
                    .findFirst();
        }

        @Override
        public UserInvitation save(UserInvitation invitation) {
            byId.put(invitation.getId(), invitation);
            return invitation;
        }

        @Override
        public void deleteByUserId(AuthUserId userId) {
            byId.values().removeIf(invitation -> invitation.getUserId().equals(userId));
        }

        @Override
        public int deleteExpiredBefore(Instant before) {
            int size = byId.size();
            byId.values().removeIf(invitation -> invitation.getExpiresAt().isBefore(before));
            return size - byId.size();
        }

        public int size() {
            return byId.size();
        }
    }

    public static final class LoginHistory implements LoginHistoryStore {

        private final List<LoginAttempt> attempts = new ArrayList<>();

        @Override
        public void append(LoginAttempt attempt) {
            attempts.add(attempt);
        }

        @Override
        public List<LoginAttempt> findRecentByUserId(AuthUserId userId, int limit) {
            return attempts.stream()
                    .filter(attempt -> userId.equals(attempt.getUserId()))
                    .sorted(Comparator.comparing(LoginAttempt::getOccurredAt).reversed())
                    .limit(limit)
                    .toList();
        }

        @Override
        public long countFailuresSince(AuthUserId userId, Instant since) {
            return attempts.stream()
                    .filter(attempt -> userId.equals(attempt.getUserId()))
                    .filter(attempt -> !attempt.isSuccessful())
                    .filter(attempt -> !attempt.getOccurredAt().isBefore(since))
                    .count();
        }

        @Override
        public int deleteBefore(Instant before) {
            int size = attempts.size();
            attempts.removeIf(attempt -> attempt.getOccurredAt().isBefore(before));
            return size - attempts.size();
        }

        public List<LoginAttempt> all() {
            return List.copyOf(attempts);
        }
    }

    public static final class Roles implements RoleStore {

        private final Map<String, Role> byCode = new LinkedHashMap<>();
        private int nextProfileCode = 1;

        @Override
        public Optional<Role> findByCode(String code) {
            return Optional.ofNullable(byCode.get(code));
        }

        @Override
        public List<Role> findByCodes(Collection<String> codes) {
            return codes.stream()
                    .map(code -> byCode.get(code.trim().toUpperCase()))
                    .filter(java.util.Objects::nonNull)
                    .toList();
        }

        @Override
        public List<Role> findAll() {
            return List.copyOf(byCode.values());
        }

        @Override
        public RoleStore.Page search(String search, String status, int page, int size, String sort, boolean ascending) {
        String query = search == null ? "" : search.trim().toLowerCase(java.util.Locale.ROOT);
        List<Role> filtered = findAll().stream()
                .filter(role -> query.isBlank() || (role.getCode() + " " + role.getName() + " "
                        + (role.getDescription() == null ? "" : role.getDescription()))
                        .toLowerCase(java.util.Locale.ROOT).contains(query))
                .filter(role -> status == null || status.isBlank() || role.getStatus().name().equalsIgnoreCase(status))
                .sorted(roleComparator(sort, ascending))
                .toList();
        int from = Math.min(page * size, filtered.size());
        int to = Math.min(from + size, filtered.size());
        return new RoleStore.Page(filtered.size(), filtered.subList(from, to));
    }

    private java.util.Comparator<Role> roleComparator(String sort, boolean ascending) {
        java.util.Comparator<Role> comparator = switch (sort == null ? "code" : sort) {
            case "name" -> java.util.Comparator.comparing(Role::getName, String.CASE_INSENSITIVE_ORDER);
            case "status" -> java.util.Comparator.comparing(role -> role.getStatus().name());
            default -> java.util.Comparator.comparing(Role::getCode, String.CASE_INSENSITIVE_ORDER);
        };
        return ascending ? comparator : comparator.reversed();
    }

        @Override
        public boolean existsByCode(String code) {
            return byCode.containsKey(code);
        }

        @Override
        public String nextProfileCode() {
            return String.format("PROF-%04d", nextProfileCode++);
        }

        @Override
        public Role save(Role role) {
            byCode.put(role.getCode(), role);
            return role;
        }
    }
}
