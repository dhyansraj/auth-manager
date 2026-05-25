package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.api.dto.MeResponse;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.security.TenantSecurity;
import io.mcpmesh.auth.manager.service.PlatformPermissions;
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
 * for platform-admin), and (c) the caller's atomic permissions (Phase A
 * of the admin-ui permission migration).
 *
 * <p>Permissions are derived from the JWT's
 * {@code resource_access.usermanagement.roles} claim, filtered to the
 * known atomic-permission catalog ({@link PlatformPermissions#ALL_KNOWN_PERMS}).
 * Composite role names (e.g. {@code tenant-admin}, {@code platform-admin})
 * are excluded -- they're delivery vehicles, not capabilities.
 *
 * <p>For platform-admin users (signed into the platform realm) we also
 * union in the full {@link PlatformPermissions#PLATFORM_PERMS} +
 * {@link PlatformPermissions#TENANT_ADMIN_BUNDLE} sets unconditionally as
 * a safety net for realms where KC's composite-role expansion isn't yet
 * wired (e.g. first deploy before {@code PlatformRoleBootstrap} runs).
 */
@RestController
public class MeController {

    private static final String USERMANAGEMENT_CLIENT = "usermanagement";
    private static final String TENANT_ADMIN_ROLE = "tenant-admin";

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
        // Pull all atomic perms from the JWT's resource_access.usermanagement.roles
        // claim (KC's composite expansion already flattened the bundles here).
        // Filter to only the recognized catalog so composite role names like
        // "tenant-admin" / "platform-admin" don't leak into the perm set.
        perms.addAll(atomicPermsFromJwt(jwt));
        // Belt-and-braces: platform-admin always sees the full catalog, even
        // if KC's composite-role wiring hasn't propagated yet on this realm.
        if (platformAdmin) {
            perms.addAll(PlatformPermissions.PLATFORM_PERMS);
            perms.addAll(PlatformPermissions.TENANT_ADMIN_BUNDLE);
        }

        String context = platformAdmin ? "platform" : "tenant";
        return new MeResponse(user, context, tenantData, platformAdmin, isTenantAdmin, perms);
    }

    /**
     * Reads {@code resource_access.usermanagement.roles}, filters to the
     * known atomic-permission catalog, and returns the matches in claim
     * order. Composite role names (e.g. {@code tenant-admin}) are excluded.
     */
    @SuppressWarnings("unchecked")
    private static Set<String> atomicPermsFromJwt(Jwt jwt) {
        Map<String, Object> ra = jwt.getClaimAsMap("resource_access");
        if (ra == null) return Set.of();
        Object client = ra.get(USERMANAGEMENT_CLIENT);
        if (!(client instanceof Map<?, ?> clientMap)) return Set.of();
        Object roles = clientMap.get("roles");
        if (!(roles instanceof List<?> roleList)) return Set.of();
        Set<String> out = new LinkedHashSet<>();
        for (Object r : roleList) {
            if (r instanceof String name && PlatformPermissions.ALL_KNOWN_PERMS.contains(name)) {
                out.add(name);
            }
        }
        return out;
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
