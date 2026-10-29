package io.github.springauth.core.identity;

import java.util.List;

/** A page of provisioned users, independent of Spring Data. */
public record ApplicationUserPage(
        int page,
        int size,
        long totalElements,
        List<ApplicationUser> content) {

    public ApplicationUserPage {
        content = content == null ? List.of() : List.copyOf(content);
    }

    public int totalPages() {
        return size == 0 ? 0 : (int) Math.ceil((double) totalElements / size);
    }
}
