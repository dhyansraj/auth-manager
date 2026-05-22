package io.mcpmesh.auth.manager.roles;

import io.mcpmesh.auth.manager.api.dto.UserResponse;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.service.TenantService;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Slug-based user view that ALWAYS includes {@code realmRoles} (composite
 * role names) plus the existing {@code roles} (system usermanagement
 * client-role names). Sibling of the older UUID-keyed
 * {@code UserManagementController} which retains its current behavior.
 *
 * <p>The PUT endpoint atomically replaces the user's manageable
 * (non-system, non-builtin) realm-role assignments.
 */
@RestController
@RequestMapping("/api/v1/tenants/{slug}/users")
public class UserRolesController {

    private static final String USERMANAGEMENT_CLIENT = "usermanagement";

    private final RolesService roles;
    private final TenantService tenants;
    private final KeycloakAdminService keycloak;

    public UserRolesController(RolesService roles, TenantService tenants, KeycloakAdminService keycloak) {
        this.roles = roles;
        this.tenants = tenants;
        this.keycloak = keycloak;
    }

    @GetMapping("/{userId}")
    @PreAuthorize("@tenantSecurity.canSeeTenantBySlug(#slug)")
    public UserResponse get(@PathVariable String slug, @PathVariable String userId) {
        Tenant t = tenants.getBySlug(slug);
        var u = keycloak.getUser(t.getRealmName(), userId);
        List<String> sysRoles = keycloak.getUserClientRoles(t.getRealmName(), userId, USERMANAGEMENT_CLIENT);
        List<String> realmRoles = roles.userManageableRealmRoles(slug, userId);
        return UserResponse.from(u, sysRoles, realmRoles);
    }

    @PutMapping("/{userId}/roles")
    @PreAuthorize("@tenantSecurity.canManageTenant(#slug)")
    public UserResponse updateRoles(
        @PathVariable String slug,
        @PathVariable String userId,
        @Valid @RequestBody UpdateUserRealmRolesRequest req,
        Authentication auth
    ) {
        roles.updateUserRoles(slug, userId, req.roleNames(), principal(auth));
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
