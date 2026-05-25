package io.mcpmesh.auth.manager.security;

import io.mcpmesh.auth.manager.keycloak.KeycloakProperties;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.service.TenantService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Exposed as the SpEL bean {@code tenantSecurity} -- the role-based authority
 * helpers used historically by {@code @PreAuthorize} annotations. As of
 * Phase B those annotations were migrated to atomic-permission checks
 * against the {@link Permissions} bean (@code @perms.*); this class stays
 * in place because admin-ui (Phase C) still references it indirectly and
 * may be invoked directly by future controllers needing role-shape rather
 * than perm-shape gates.
 *
 * <p>Verifies (a) the caller has a JWT, (b) that JWT was issued by the
 * target tenant's realm, and (c) the JWT's {@code resource_access.usermanagement.roles}
 * claim contains the named role.
 */
@Component("tenantSecurity")
public class TenantSecurity {

    private static final Logger log = LoggerFactory.getLogger(TenantSecurity.class);
    private static final String USERMANAGEMENT_CLIENT = "usermanagement";
    private static final String TENANT_REALM_PREFIX = "t-";

    private final TenantService tenants;
    private final TenantRepository tenantRepository;
    private final KeycloakProperties keycloak;

    public TenantSecurity(TenantService tenants, TenantRepository tenantRepository,
                          KeycloakProperties keycloak) {
        this.tenants = tenants;
        this.tenantRepository = tenantRepository;
        this.keycloak = keycloak;
    }

    public boolean hasRole(UUID tenantId, String roleName) {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (!(auth instanceof JwtAuthenticationToken jwtAuth)) {
            log.debug("hasRole({},{}): no JWT in context", tenantId, roleName);
            return false;
        }
        if (isPlatformAdmin(jwtAuth.getToken())) {
            log.debug("hasRole({},{}): granted via platform-admin bypass", tenantId, roleName);
            return true;
        }
        var tenant = tenants.get(tenantId);  // throws TenantNotFoundException -> 404 (handled by GlobalExceptionHandler)
        return checkRoleClaim(jwtAuth.getToken(), tenant.getRealmName(), roleName);
    }

    /**
     * Slug-keyed lookup used by controllers whose path variable is the
     * tenant slug (e.g. {@code /api/v1/tenants/{slug}/routes}).
     *
     * <p>Named distinctly from {@link #hasRole(UUID, String)} to avoid
     * SpEL ambiguity -- otherwise an expression like
     * {@code @tenantSecurity.hasRole(#slug, 'tenant-admin')} where
     * {@code #slug} is a {@code String} can be matched against the
     * {@code UUID} overload and trigger a conversion failure.
     */
    public boolean hasRoleBySlug(String slug, String roleName) {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (!(auth instanceof JwtAuthenticationToken jwtAuth)) {
            log.debug("hasRole({},{}): no JWT in context", slug, roleName);
            return false;
        }
        if (isPlatformAdmin(jwtAuth.getToken())) {
            log.debug("hasRoleBySlug({},{}): granted via platform-admin bypass", slug, roleName);
            return true;
        }
        var tenant = tenants.getBySlug(slug);
        return checkRoleClaim(jwtAuth.getToken(), tenant.getRealmName(), roleName);
    }

    /**
     * True when the caller's JWT was issued by the configured "platform"
     * realm AND carries the configured platform-admin realm role. This is
     * the cross-tenant super-admin bypass used by the admin-ui. Public so
     * controllers can branch on it directly (e.g. "list all tenants for
     * platform-admin, else list just my own").
     */
    public boolean isPlatformAdmin() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (!(auth instanceof JwtAuthenticationToken jwtAuth)) {
            return false;
        }
        return isPlatformAdmin(jwtAuth.getToken());
    }

    /**
     * The tenant the current caller belongs to, derived from the JWT issuer's
     * realm name (e.g. issuer ".../realms/t-app1" -> realm "t-app1" -> tenant
     * with realmName "t-app1"). Returns empty if there is no JWT, the realm
     * doesn't match the {@code t-<slug>} convention, or no tenant exists with
     * that realmName.
     *
     * <p>NOTE: platform-admin users (signed into the platform realm) DO NOT
     * have an associated tenant. Callers should always check
     * {@link #isPlatformAdmin()} first.
     */
    public Optional<UUID> currentTenantId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!(auth instanceof JwtAuthenticationToken jwtAuth)) {
            return Optional.empty();
        }
        Jwt jwt = jwtAuth.getToken();
        if (jwt == null || jwt.getIssuer() == null) {
            return Optional.empty();
        }
        String issuer = jwt.getIssuer().toString();
        int idx = issuer.indexOf("/realms/");
        if (idx < 0) {
            return Optional.empty();
        }
        String realm = issuer.substring(idx + "/realms/".length());
        if (realm.endsWith("/")) {
            realm = realm.substring(0, realm.length() - 1);
        }
        if (!realm.startsWith(TENANT_REALM_PREFIX)) {
            return Optional.empty();
        }
        return tenantRepository.findByRealmNameAndDeletedAtIsNull(realm)
            .map(t -> t.getId());
    }

    /**
     * True if the caller is allowed to see the given tenant -- either
     * because they're platform-admin (see all) or because the tenant
     * matches their JWT realm.
     */
    public boolean canSeeTenant(UUID tenantId) {
        if (isPlatformAdmin()) return true;
        return currentTenantId().map(id -> id.equals(tenantId)).orElse(false);
    }

    /**
     * Convenience: lookup by slug, then check visibility. Returns false on
     * missing tenant so unauthorized callers see 403 rather than 404 (which
     * would leak existence).
     */
    public boolean canSeeTenantBySlug(String slug) {
        if (isPlatformAdmin()) return true;
        return tenantRepository.findBySlugAndDeletedAtIsNull(slug)
            .map(t -> canSeeTenant(t.getId()))
            .orElse(false);
    }

    /**
     * True when the caller is allowed to mutate the given tenant -- either
     * platform-admin (anywhere) or tenant-admin of that specific tenant.
     * Used by composite-role + user-role endpoints whose write methods
     * require admin authority.
     */
    public boolean canManageTenant(String slug) {
        return hasRoleBySlug(slug, "tenant-admin");
    }

    /**
     * True when the caller is allowed to manage users in the given tenant.
     * Granted to: platform-admin (anywhere), tenant-admin of this tenant,
     * tenant-user-manager of this tenant. Lighter-weight than
     * {@link #canManageTenant(String)} which also covers Routes/IdP/Branding/
     * Permissions/Roles config.
     */
    public boolean canManageUsersInTenant(String slug) {
        if (isPlatformAdmin()) return true;
        if (hasRoleBySlug(slug, "tenant-admin")) return true;
        return hasRoleBySlug(slug, "tenant-user-manager");
    }

    /**
     * UUID-keyed twin of {@link #canManageUsersInTenant(String)}, for the
     * UUID-keyed user-management controller.
     */
    public boolean canManageUsersInTenantId(UUID tenantId) {
        if (isPlatformAdmin()) return true;
        if (hasRole(tenantId, "tenant-admin")) return true;
        return hasRole(tenantId, "tenant-user-manager");
    }

    /**
     * Returns true when the caller's JWT was issued by the configured
     * "platform" realm AND carries the configured platform-admin realm role.
     * This is the cross-tenant super-admin bypass used by the admin-ui.
     */
    private boolean isPlatformAdmin(Jwt jwt) {
        if (jwt == null) return false;
        var platform = keycloak.platform();
        if (platform == null) return false;
        String issuer = jwt.getIssuer() == null ? "" : jwt.getIssuer().toString();
        String expected = trim(keycloak.url()) + "/realms/" + platform.realm();
        if (!issuer.equals(expected) && !issuer.equals(expected + "/")) {
            return false;
        }
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        if (realmAccess == null) return false;
        Object roles = realmAccess.get("roles");
        if (!(roles instanceof List<?> roleList)) return false;
        return roleList.contains(platform.role());
    }

    private boolean checkRoleClaim(Jwt jwt, String expectedRealmName, String roleName) {
        String issuer = jwt.getIssuer() == null ? "" : jwt.getIssuer().toString();
        String expected = trim(keycloak.url()) + "/realms/" + expectedRealmName;
        if (!issuer.equals(expected) && !issuer.equals(expected + "/")) {
            log.debug("hasRole denied: issuer {} != expected {}", issuer, expected);
            return false;
        }

        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess == null) return false;
        Object usermgmt = resourceAccess.get(USERMANAGEMENT_CLIENT);
        if (!(usermgmt instanceof Map<?, ?> umMap)) return false;
        Object roles = umMap.get("roles");
        if (!(roles instanceof List<?> roleList)) return false;
        return roleList.contains(roleName);
    }

    private static String trim(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }
}
