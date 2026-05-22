package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.api.dto.MeResponse;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.security.TenantSecurity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Self-description endpoint for the auth-manager's admin UI. Returns a
 * union of (a) the JWT-derived user, (b) tenant resolution (or {@code null}
 * for platform-admin), and (c) a capability set the UI uses to gate menus.
 *
 * <p>Unlike the tenant apps, this endpoint does NOT call Keycloak's UMA
 * endpoint: the platform (and dev/master) realms intentionally have no
 * authz services configured, so the capability set is derived from the
 * caller's roles (platform-admin in the platform realm, tenant-admin via
 * the {@code usermanagement} client in the tenant realm).
 */
@RestController
public class MeController {

    private static final String USERMANAGEMENT_CLIENT = "usermanagement";
    private static final String TENANT_ADMIN_ROLE = "tenant-admin";

    private static final Set<String> PLATFORM_ADMIN_CAPABILITIES = Set.of(
        "TENANT_LIST_ALL",
        "TENANT_CREATE",
        "TENANT_DELETE",
        "TENANT_VIEW_ANY",
        "USER_INVITE_ANY",
        "AUDIT_VIEW_ALL"
    );

    private static final Set<String> TENANT_ADMIN_CAPABILITIES = Set.of(
        "TENANT_VIEW_OWN",
        "ROUTES_EDIT",
        "USER_INVITE_OWN",
        "AUDIT_VIEW_OWN"
    );

    private final TenantSecurity tenantSecurity;
    private final TenantRepository tenantRepository;

    public MeController(TenantSecurity tenantSecurity, TenantRepository tenantRepository) {
        this.tenantSecurity = tenantSecurity;
        this.tenantRepository = tenantRepository;
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/api/v1/me")
    public MeResponse me(@AuthenticationPrincipal Jwt jwt) {
        MeResponse.User user = new MeResponse.User(
            jwt.getSubject(),
            jwt.getClaimAsString("email"),
            jwt.getClaimAsString("preferred_username"),
            jwt.getClaimAsString("name")
        );

        boolean platformAdmin = tenantSecurity.isPlatformAdmin();

        MeResponse.Tenant tenantData = null;
        if (!platformAdmin) {
            tenantData = tenantSecurity.currentTenantId()
                .flatMap(tenantRepository::findById)
                .map(t -> new MeResponse.Tenant(
                    t.getId().toString(), t.getSlug(), t.getDisplayName(), t.getRealmName()))
                .orElse(null);
        }

        boolean isTenantAdmin = hasUsermanagementRole(jwt, TENANT_ADMIN_ROLE);

        Set<String> perms = new LinkedHashSet<>();
        if (platformAdmin) perms.addAll(PLATFORM_ADMIN_CAPABILITIES);
        if (isTenantAdmin) perms.addAll(TENANT_ADMIN_CAPABILITIES);

        String context = platformAdmin ? "platform" : "tenant";
        return new MeResponse(user, context, tenantData, platformAdmin, isTenantAdmin, perms);
    }

    @SuppressWarnings("unchecked")
    private static boolean hasUsermanagementRole(Jwt jwt, String role) {
        Map<String, Object> ra = jwt.getClaimAsMap("resource_access");
        if (ra == null) return false;
        Object client = ra.get(USERMANAGEMENT_CLIENT);
        if (!(client instanceof Map<?, ?> clientMap)) return false;
        Object roles = clientMap.get("roles");
        if (!(roles instanceof List<?> roleList)) return false;
        return roleList.contains(role);
    }
}
