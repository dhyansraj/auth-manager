package io.mcpmesh.app1.api;

import io.mcpmesh.auth.lib.Permissions;
import io.mcpmesh.auth.lib.dto.MeResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Tenant-app self-description endpoint. The UI calls this once on load to
 * decide which features to expose without having to decode the JWT or
 * call Keycloak's UMA endpoint itself.
 *
 * <p>This app (app1-backend) lives entirely inside one tenant realm
 * ({@code t-app1}) so the tenant identity is injected from configuration,
 * not derived from the JWT. {@code permissions} are aggregated by
 * {@link Permissions} across all UMA audiences configured for this app
 * (default: just this app's own {@code auth-lib.client-id}).
 */
@RestController
public class MeController {

    private static final String USERMANAGEMENT_CLIENT = "usermanagement";
    private static final String TENANT_ADMIN_ROLE = "tenant-admin";

    private final Permissions permissions;

    @Value("${app1.tenant.id:}")
    private String tenantId;
    @Value("${app1.tenant.slug:app1}")
    private String slug;
    @Value("${app1.tenant.display-name:App One}")
    private String displayName;
    @Value("${app1.tenant.realm-name:t-app1}")
    private String realmName;

    public MeController(Permissions permissions) {
        this.permissions = permissions;
    }

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/api/me")
    public MeResponse me(@AuthenticationPrincipal Jwt jwt) {
        MeResponse.User user = new MeResponse.User(
            jwt.getSubject(),
            jwt.getClaimAsString("email"),
            jwt.getClaimAsString("preferred_username"),
            jwt.getClaimAsString("name")
        );
        MeResponse.Tenant tenant = new MeResponse.Tenant(
            tenantId, slug, displayName, realmName);

        boolean isTenantAdmin = hasUsermanagementRole(jwt, TENANT_ADMIN_ROLE);

        Set<String> perms = permissions.allFor(jwt);
        return new MeResponse(user, "tenant", tenant, false, isTenantAdmin, perms);
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
