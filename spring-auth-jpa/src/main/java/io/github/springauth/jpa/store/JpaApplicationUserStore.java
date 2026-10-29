package io.github.springauth.jpa.store;

import io.github.springauth.core.identity.*;
import io.github.springauth.jpa.entity.ApplicationUserEntity;
import jakarta.persistence.EntityManager;
import java.util.Optional;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Transactional(propagation=Propagation.MANDATORY)
public class JpaApplicationUserStore implements ApplicationUserStore {
    private static final String NO_FILTER = "__NO_FILTER__";
    private final EntityManager em;
    public JpaApplicationUserStore(EntityManager em) { this.em=em; }
    public Optional<ApplicationUser> findByLogin(String login) { return em.createQuery("select u from ApplicationUserEntity u where lower(u.login)=lower(:login)",ApplicationUserEntity.class).setParameter("login",login).setMaxResults(1).getResultStream().findFirst().map(ApplicationUserEntity::domain); }
    public Optional<ApplicationUser> findByExternalSubject(String subject) { return em.createQuery("select u from ApplicationUserEntity u where u.externalSubject=:subject",ApplicationUserEntity.class).setParameter("subject",subject).setMaxResults(1).getResultStream().findFirst().map(ApplicationUserEntity::domain); }
    public Optional<ApplicationUser> findById(java.util.UUID id) { return Optional.ofNullable(em.find(ApplicationUserEntity.class,id)).map(ApplicationUserEntity::domain); }
    public java.util.List<ApplicationUser> findAll() { return em.createQuery("select u from ApplicationUserEntity u order by u.login",ApplicationUserEntity.class).getResultList().stream().map(ApplicationUserEntity::domain).toList(); }
    @Override
    public java.util.List<String> findDistinctDirections() {
        return em.createQuery("select distinct u.direction from ApplicationUserEntity u "
                        + "where u.direction is not null order by u.direction", String.class)
                .getResultList();
    }
    @Override
    public ApplicationUserStatistics statistics() {
        long total = em.createQuery("select count(u) from ApplicationUserEntity u", Long.class).getSingleResult();
        var counts = em.createQuery("select u.status, count(u) from ApplicationUserEntity u group by u.status", Object[].class)
                .getResultList();
        long active = 0, disabled = 0, locked = 0, pendingMfa = 0;
        for (Object[] row : counts) {
            long count = ((Number) row[1]).longValue();
            switch (String.valueOf(row[0])) {
                case "ACTIVE" -> active = count;
                case "DISABLED" -> disabled = count;
                case "LOCKED" -> locked = count;
                case "PENDING_MFA" -> pendingMfa = count;
                default -> { }
            }
        }
        return new ApplicationUserStatistics(total, active, disabled, locked, pendingMfa);
    }
    @Override
    public ApplicationUserPage search(String search, UserStatus status, String direction,
                                      int page, int size, String sort, boolean ascending) {
        String normalizedSearch = search == null ? "" : search.trim().toLowerCase(java.util.Locale.ROOT);
        String searchFilter = normalizedSearch.isBlank() ? NO_FILTER : normalizedSearch;
        String query = "%" + normalizedSearch + "%";
        String directionFilter = direction == null || direction.isBlank() ? NO_FILTER : direction.trim();
        String statusFilter = status == null ? NO_FILTER : status.name();
        String where = " where (:searchFilter = '" + NO_FILTER + "' or lower(u.login) like :query or lower(coalesce(u.displayName, '')) like :query "
                + "or lower(coalesce(u.email, '')) like :query or lower(coalesce(u.direction, '')) like :query "
                + "or lower(coalesce(u.title, '')) like :query or lower(role) like :query) "
                + "and (:statusFilter = '" + NO_FILTER + "' or u.status = :statusFilter) "
                + "and (:directionFilter = '" + NO_FILTER + "' or lower(u.direction) = lower(:directionFilter))";
        String orderColumn = switch (sort == null ? "login" : sort) {
            case "displayName" -> "u.displayName";
            case "email" -> "u.email";
            case "direction" -> "u.direction";
            case "status" -> "u.status";
            default -> "u.login";
        };
        String order = orderColumn + (ascending ? " asc" : " desc") + ", u.login asc";
        var contentQuery = em.createQuery("select distinct u from ApplicationUserEntity u left join u.roleCodes role" + where + " order by " + order, ApplicationUserEntity.class)
                .setParameter("searchFilter", searchFilter)
                .setParameter("query", query)
                .setParameter("statusFilter", statusFilter)
                .setParameter("directionFilter", directionFilter)
                .setFirstResult(page * size)
                .setMaxResults(size);
        var content = contentQuery.getResultList().stream().map(ApplicationUserEntity::domain).toList();
        long total = em.createQuery("select count(distinct u.id) from ApplicationUserEntity u left join u.roleCodes role" + where, Long.class)
                .setParameter("searchFilter", searchFilter)
                .setParameter("query", query)
                .setParameter("statusFilter", statusFilter)
                .setParameter("directionFilter", directionFilter)
                .getSingleResult();
        return new ApplicationUserPage(page, size, total, content);
    }
    public ApplicationUser save(ApplicationUser u) {
        var existing = em.find(ApplicationUserEntity.class, u.id());
        if (existing == null) {
            em.persist(ApplicationUserEntity.from(u));
        } else {
            // Merge the full local authorization record explicitly. Changes to MFA policy and
            // roles are security-sensitive and the calling API must not acknowledge them before
            // database has accepted the new state.
            em.merge(ApplicationUserEntity.from(u));
        }
        em.flush();
        return u;
    }
}
