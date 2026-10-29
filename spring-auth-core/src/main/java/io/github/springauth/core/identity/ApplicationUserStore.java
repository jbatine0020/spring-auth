package io.github.springauth.core.identity;

import java.util.Comparator;
import java.util.Locale;
import java.util.Optional;
import java.util.Objects;

public interface ApplicationUserStore {
    Optional<ApplicationUser> findByLogin(String login);
    Optional<ApplicationUser> findByExternalSubject(String externalSubject);
    Optional<ApplicationUser> findById(java.util.UUID id);
    java.util.List<ApplicationUser> findAll();
    default java.util.List<String> findDistinctDirections() {
        return findAll().stream()
                .map(ApplicationUser::direction)
                .filter(direction -> direction != null && !direction.isBlank())
                .distinct()
                .sorted(String.CASE_INSENSITIVE_ORDER)
                .toList();
    }
    default ApplicationUserStatistics statistics() {
        var users = findAll();
        return new ApplicationUserStatistics(
                users.size(),
                users.stream().filter(u -> u.status() == UserStatus.ACTIVE).count(),
                users.stream().filter(u -> u.status() == UserStatus.DISABLED).count(),
                users.stream().filter(u -> u.status() == UserStatus.LOCKED).count(),
                users.stream().filter(u -> u.status() == UserStatus.PENDING_MFA).count());
    }
    default ApplicationUserPage search(String search, UserStatus status, String direction,
                                       int page, int size, String sort, boolean ascending) {
        String query = search == null ? "" : search.trim().toLowerCase(Locale.ROOT);
        var filtered = findAll().stream()
                .filter(user -> query.isBlank() || searchable(user).contains(query))
                .filter(user -> status == null || user.status() == status)
                .filter(user -> direction == null || direction.isBlank()
                        || direction.equalsIgnoreCase(Objects.toString(user.direction(), "")))
                .sorted(comparator(sort, ascending))
                .toList();
        int from = Math.min(page * size, filtered.size());
        int to = Math.min(from + size, filtered.size());
        return new ApplicationUserPage(page, size, filtered.size(), filtered.subList(from, to));
    }

    private static String searchable(ApplicationUser user) {
        return String.join(" ", Objects.toString(user.login(), ""),
                Objects.toString(user.displayName(), ""), Objects.toString(user.email(), ""),
                Objects.toString(user.direction(), ""), Objects.toString(user.title(), ""),
                String.join(" ", user.roleCodes())).toLowerCase(Locale.ROOT);
    }

    private static Comparator<ApplicationUser> comparator(String sort, boolean ascending) {
        Comparator<ApplicationUser> comparator = switch (sort == null ? "login" : sort) {
            case "displayName" -> Comparator.comparing(u -> Objects.toString(u.displayName(), ""), String.CASE_INSENSITIVE_ORDER);
            case "email" -> Comparator.comparing(u -> Objects.toString(u.email(), ""), String.CASE_INSENSITIVE_ORDER);
            case "direction" -> Comparator.comparing(u -> Objects.toString(u.direction(), ""), String.CASE_INSENSITIVE_ORDER);
            case "status" -> Comparator.comparing(u -> u.status().name());
            default -> Comparator.comparing(ApplicationUser::login, String.CASE_INSENSITIVE_ORDER);
        };
        return ascending ? comparator : comparator.reversed();
    }
    ApplicationUser save(ApplicationUser user);
}
