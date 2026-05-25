package io.mcpmesh.auth.manager.roles;

import io.mcpmesh.auth.manager.api.dto.UserResponse;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.security.Permissions;
import io.mcpmesh.auth.manager.service.TenantService;
import io.mcpmesh.auth.manager.service.UserManagementService;
import jakarta.validation.Valid;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Slug-based user view that ALWAYS includes {@code realmRoles} (composite
 * role names) plus the existing {@code roles} (system usermanagement
 * client-role names). Sibling of the older UUID-keyed
 * {@code UserManagementController} which retains its current behavior.
 *
 * <p>The PUT endpoint atomically replaces the user's manageable
 * (non-system, non-builtin) realm-role assignments. When the request body
 * also carries a non-null {@code systemRoles} list, the endpoint additionally
 * reconciles the user's manageable system client roles
 * ({@code tenant-admin}, {@code tenant-user-manager}) -- and requires the
 * stricter {@code canManageTenant} authority for that privileged path.
 */
@RestController
@RequestMapping("/api/v1/tenants/{slug:(?!^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$)[a-zA-Z0-9_-]+}/users")
public class UserRolesController {

    private static final String USERMANAGEMENT_CLIENT = "usermanagement";

    private final RolesService roles;
    private final TenantService tenants;
    private final KeycloakAdminService keycloak;
    private final Permissions perms;
    private final UserManagementService users;

    public UserRolesController(RolesService roles, TenantService tenants,
                               KeycloakAdminService keycloak,
                               Permissions perms,
                               UserManagementService users) {
        this.roles = roles;
        this.tenants = tenants;
        this.keycloak = keycloak;
        this.perms = perms;
        this.users = users;
    }

    /**
     * Slug-keyed user list intended for tenant-app backends with a service
     * account (and the admin UI's slug-based surface). Pageable, search-able,
     * optionally filtered by realm composite role.
     *
     * <p>Service-account callers from a tenant client (issuer
     * {@code t-<slug>}) holding {@code USER_LIST} pass the gate the same way
     * a human tenant-admin / tenant-user-manager does -- the perm check is
     * a pure presence check on the JWT's
     * {@code resource_access.usermanagement.roles} claim, scoped to the
     * tenant's realm by {@link Permissions#hasOnTenant}.
     *
     * <p>{@code includeRealmRoles} defaults to true (this surface's whole
     * value-add over the UUID-keyed sibling); set it false for a slight perf
     * win when the caller only needs username/email/system-roles.
     */
    @GetMapping
    @PreAuthorize("@perms.hasOnTenant(#slug, 'USER_LIST')")
    public Map<String, Object> list(
        @PathVariable String slug,
        @RequestParam(required = false) String role,
        @RequestParam(required = false) String search,
        @RequestParam(defaultValue = "0") int first,
        @RequestParam(defaultValue = "50") int max,
        @RequestParam(defaultValue = "true") boolean includeRealmRoles
    ) {
        int safeMax = Math.min(Math.max(max, 1), 200);
        var result = users.listWithRoles(slug, role, search, first, safeMax, includeRealmRoles);
        return Map.of(
            "items", result.items(),
            "first", result.first(),
            "max", result.max(),
            "totalItems", result.totalItems()
        );
    }

    @GetMapping("/{userId}")
    @PreAuthorize("@perms.hasOnTenant(#slug, 'USER_LIST')")
    public UserResponse get(@PathVariable String slug, @PathVariable String userId) {
        Tenant t = tenants.getBySlug(slug);
        var u = keycloak.getUser(t.getRealmName(), userId);
        List<String> sysRoles = keycloak.getUserClientRoles(t.getRealmName(), userId, USERMANAGEMENT_CLIENT);
        List<String> realmRoles = roles.userManageableRealmRoles(slug, userId);
        return UserResponse.from(u, sysRoles, realmRoles);
    }

    /**
     * Atomic-replace the user's role assignments.
     *
     * <p>Authorization rules:
     * <ul>
     *   <li>Baseline gate {@code canManageUsersInTenant}: tenant-admin,
     *       tenant-user-manager, or platform-admin -- enforced via
     *       {@link PreAuthorize}.</li>
     *   <li>Privileged gate {@code canManageTenant}: tenant-admin or
     *       platform-admin -- enforced inline, only when the request body
     *       contains a non-null {@code systemRoles} list. This prevents
     *       tenant-user-manager holders from minting new tenant-admins
     *       (privilege escalation).</li>
     * </ul>
     */
    @PutMapping("/{userId}/roles")
    @PreAuthorize("@perms.hasOnTenant(#slug, 'USER_REALM_ROLE_ASSIGN')")
    public UserResponse updateRoles(
        @PathVariable String slug,
        @PathVariable String userId,
        @Valid @RequestBody UpdateUserRealmRolesRequest req,
        Authentication auth
    ) {
        String actor = principal(auth);

        // Stricter gate for the privileged system-role path. Spring's
        // @PreAuthorize already checked the lighter USER_REALM_ROLE_ASSIGN;
        // we layer USER_SYSTEM_ROLE_ASSIGN on top here so tenant-user-manager
        // callers can't grant/revoke tenant-admin or tenant-user-manager.
        if (req.systemRoles() != null && !perms.hasOnTenant(slug, "USER_SYSTEM_ROLE_ASSIGN")) {
            throw new AccessDeniedException(
                "System roles can only be managed by tenant-admin or platform-admin");
        }

        roles.updateUserRoles(slug, userId, req.roleNames(), actor);
        if (req.systemRoles() != null) {
            roles.updateUserSystemRoles(slug, userId, req.systemRoles(), actor);
        }
        return get(slug, userId);
    }

    private static String principal(Authentication auth) {
        if (auth instanceof JwtAuthenticationToken jwtAuth) {
            Jwt jwt = jwtAuth.getToken();
            String pref = jwt.getClaimAsString("preferred_username");
            return pref != null ? pref : jwt.getSubject();
        }
        return "system";
    }
}
