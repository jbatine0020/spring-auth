package io.github.springauth.web.controller;

import java.util.List;
import java.util.Set;

import jakarta.validation.constraints.NotBlank;
import io.github.springauth.core.service.RoleService;
import io.github.springauth.web.dto.AuthResponses;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.transaction.annotation.Transactional;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

/**
 * Role administration.
 *
 * <p>Permission changes reach a user with their next access token, so within the access TTL.
 * Revoke their sessions through the admin controller when a withdrawal has to be immediate.
 */
@RestController
@RequestMapping("${spring-auth.web.base-path:/api/v1/auth}/roles")
@Tag(name = "Roles", description = "Role and permission administration")
@SecurityRequirement(name = "bearerAuth")
public class RoleController {

    private final RoleService roleService;

    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    @GetMapping
    @Transactional(readOnly = true)
    @Operation(summary = "List roles", description = "Returns all active and archived roles. Requires the roles:read permission.")
    @PreAuthorize("hasAuthority('" + AuthPermissions.ROLES_READ + "')")
    public ResponseEntity<List<AuthResponses.RoleResponse>> list() {
        return ResponseEntity.ok(roleService.list().stream()
                .map(AuthResponses.RoleResponse::from)
                .toList());
    }

    @GetMapping("/search")
    @Transactional(readOnly = true)
    @Operation(summary = "Search roles with pagination")
    @PreAuthorize("hasAuthority('" + AuthPermissions.ROLES_READ + "')")
    public ResponseEntity<Envelope<AuthResponses.RolePageResponse>> search(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "code,asc") String sort) {
        int safePage = Math.max(page, 0);
        int safeSize = Math.min(Math.max(size, 1), 100);
        String[] sortParts = sort.split(",", 2);
        boolean ascending = sortParts.length < 2 || !"desc".equalsIgnoreCase(sortParts[1]);
        return ResponseEntity.ok(Envelope.success("Profils récupérés avec succès",
                AuthResponses.RolePageResponse.from(roleService.search(search, status, safePage, safeSize,
                        sortParts[0], ascending))));
    }

    @GetMapping("/{code}")
    @Transactional(readOnly = true)
    @Operation(summary = "Get a role", description = "Returns one role and its permission set by code.")
    @PreAuthorize("hasAuthority('" + AuthPermissions.ROLES_READ + "')")
    public ResponseEntity<AuthResponses.RoleResponse> get(@PathVariable String code) {
        return ResponseEntity.ok(AuthResponses.RoleResponse.from(roleService.get(code)));
    }

    @PostMapping
    @Operation(summary = "Create a role", description = "Creates a role with its initial permission set. Example: {\"code\":\"APP_USER\",\"name\":\"Application user\",\"permissions\":[\"payments:read\"]}.")
    @PreAuthorize("hasAuthority('" + AuthPermissions.ROLES_WRITE + "')")
    public ResponseEntity<AuthResponses.RoleResponse> create(@RequestBody CreateRole request) {
        return ResponseEntity.ok(AuthResponses.RoleResponse.from(roleService.createGenerated(
                request.name(), request.description(), request.permissions())));
    }

    @PutMapping("/{code}")
    @PreAuthorize("hasAuthority('" + AuthPermissions.ROLES_WRITE + "')")
    public ResponseEntity<AuthResponses.RoleResponse> rename(@PathVariable String code,
                                                             @RequestBody RenameRole request) {
        return ResponseEntity.ok(AuthResponses.RoleResponse.from(
                roleService.rename(code, request.name(), request.description())));
    }

    /** Replaces the permission set wholesale. There is no partial update. */
    @PutMapping("/{code}/permissions")
    @Operation(summary = "Replace role permissions", description = "Replaces the complete permission set; this is not a partial update.")
    @PreAuthorize("hasAuthority('" + AuthPermissions.ROLES_WRITE + "')")
    public ResponseEntity<AuthResponses.RoleResponse> replacePermissions(
            @PathVariable String code,
            @RequestBody ReplacePermissions request) {
        return ResponseEntity.ok(AuthResponses.RoleResponse.from(
                roleService.replacePermissions(code, request.permissions())));
    }

    @PostMapping("/{code}:archive")
    @PreAuthorize("hasAuthority('" + AuthPermissions.ROLES_WRITE + "')")
    public ResponseEntity<AuthResponses.RoleResponse> archive(@PathVariable String code) {
        return ResponseEntity.ok(AuthResponses.RoleResponse.from(roleService.archive(code)));
    }

    @PostMapping("/{code}:restore")
    @PreAuthorize("hasAuthority('" + AuthPermissions.ROLES_WRITE + "')")
    public ResponseEntity<AuthResponses.RoleResponse> restore(@PathVariable String code) {
        return ResponseEntity.ok(AuthResponses.RoleResponse.from(roleService.restore(code)));
    }

    public record CreateRole(
            @NotBlank String name,
            String description,
            Set<String> permissions) {}

    public record RenameRole(@NotBlank String name, String description) {}

    public record ReplacePermissions(Set<String> permissions) {}

    public record Envelope<T>(boolean success, String message, T result) {
        static <T> Envelope<T> success(String message, T result) { return new Envelope<>(true, message, result); }
    }
}
