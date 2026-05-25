package io.mcpmesh.auth.manager.security;

import io.mcpmesh.auth.manager.keycloak.KeycloakProperties;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
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
 * Exposed as the SpEL bean {@code perms} so controllers can write:
 * {@code @PreAuthorize("@perms.hasOnTenant(#slug, 'ROUTES_EDIT')")}.
 *
 * <p>Atomic-permission counterpart to {@link TenantSecurity}'s role-based
 * helpers. After Phase A, KC's composite-role expansion flattens the
 * {@code tenant-admin} / {@code tenant-user-manager} / {@code platform-admin}
 * composites into the JWT's {@code resource_access.usermanagement.roles}
 * claim, so a presence check on that claim is all we need.
 *
 * <p>Why this lives alongside {@link TenantSecurity} rather than replacing it:
 * the admin-ui (Phase C) still references {@code TenantSecurity} from places
 * outside {@code @PreAuthorize} annotations -- the role-based helpers stay
 * during the transition.
 */
@Component("perms")
public class Permissions {

    private static final Logger log = LoggerFactory.getLogger(Permissions.class);
    private static final String USERMANAGEMENT_CLIENT = "usermanagement";
    private static final String TENANT_REALM_PREFIX = "t-";

    private final TenantRepository tenantRepository;
    private final KeycloakProperties keycloak;

    public Permissions(TenantRepository tenantRepository, KeycloakProperties keycloak) {
        this.tenantRepository = tenantRepository;
        this.keycloak = keycloak;
    }

    /**
     * True when the caller's JWT carries the given atomic permission in its
     * {@code resource_access.usermanagement.roles} claim. Works for any JWT
     * issuer (platform or tenant) -- KC's composite-role expansion has
     * already flattened the perm into the claim if the user holds an
     * eligible composite role.
     *
     * <p>This is a pure presence check on the JWT claim. There is no
     * implicit tenant scoping -- use {@link #hasOnTenant(String, String)}
     * or {@link #hasOnTenantId(UUID, String)} for tenant-scoped guards.
     */
    public boolean has(String permission) {
        Jwt jwt = currentJwt();
        if (jwt == null) {
            log.debug("has({}): no JWT in context", permission);
            return false;
        }
        return rolesFromUsermanagement(jwt).contains(permission);
    }

    /**
     * Tenant-scoped variant keyed by slug. Passes iff:
     * <ul>
     *   <li>caller is platform-admin (issuer = platform realm + has the
     *       platform-admin realm role) -- bypass for any slug, OR</li>
     *   <li>caller's JWT issuer realm matches the tenant's realm AND the
     *       permission is present in the {@code usermanagement} client roles
     *       claim.</li>
     * </ul>
     *
     * <p>Returns false on missing tenant so unauthorized callers see 403
     * rather than 404 (which would leak existence).
     */
    public boolean hasOnTenant(String slug, String permission) {
        Jwt jwt = currentJwt();
        if (jwt == null) return false;
        if (isPlatformAdminJwt(jwt)) return true;
        if (!rolesFromUsermanagement(jwt).contains(permission)) return false;
        return tenantRepository.findBySlugAndDeletedAtIsNull(slug)
            .map(t -> jwtRealmMatches(jwt, t.getRealmName()))
            .orElse(false);
    }

    /**
     * UUID-keyed twin of {@link #hasOnTenant(String, String)}, for
     * controllers whose path variable is a tenant id (e.g.
     * {@code /api/v1/tenants/{tenantId}/users}).
     */
    public boolean hasOnTenantId(UUID tenantId, String permission) {
        Jwt jwt = currentJwt();
        if (jwt == null) return false;
        if (isPlatformAdminJwt(jwt)) return true;
        if (!rolesFromUsermanagement(jwt).contains(permission)) return false;
        return tenantRepository.findById(tenantId)
            .filter(t -> t.getDeletedAt() == null)
            .map(t -> jwtRealmMatches(jwt, t.getRealmName()))
            .orElse(false);
    }

    // ----- helpers ----------------------------------------------------------

    private static Jwt currentJwt() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!(auth instanceof JwtAuthenticationToken jwtAuth)) return null;
        return jwtAuth.getToken();
    }

    @SuppressWarnings("unchecked")
    private static List<String> rolesFromUsermanagement(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess == null) return List.of();
        Object usermgmt = resourceAccess.get(USERMANAGEMENT_CLIENT);
        if (!(usermgmt instanceof Map<?, ?> umMap)) return List.of();
        Object roles = umMap.get("roles");
        if (!(roles instanceof List<?> roleList)) return List.of();
        return (List<String>) roleList;
    }

    /**
     * Mirrors {@code TenantSecurity#isPlatformAdmin(Jwt)}: caller's JWT was
     * issued by the configured "platform" realm AND carries the configured
     * platform-admin realm role.
     */
    private boolean isPlatformAdminJwt(Jwt jwt) {
        if (jwt == null) return false;
        var platform = keycloak.platform();
        if (platform == null) return false;
        String issuer = jwt.getIssuer() == null ? "" : jwt.getIssuer().toString();
        String expected = trim(keycloak.url()) + "/realms/" + platform.realm();
        if (!issuer.equals(expected) && !issuer.equals(expected + "/")) return false;
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        if (realmAccess == null) return false;
        Object roles = realmAccess.get("roles");
        if (!(roles instanceof List<?> roleList)) return false;
        return roleList.contains(platform.role());
    }

    /** True when the JWT's issuer realm equals the expected tenant realm. */
    private boolean jwtRealmMatches(Jwt jwt, String expectedRealmName) {
        String issuer = jwt.getIssuer() == null ? "" : jwt.getIssuer().toString();
        String expected = trim(keycloak.url()) + "/realms/" + expectedRealmName;
        return issuer.equals(expected) || issuer.equals(expected + "/");
    }

    private static String trim(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    /**
     * Visible for testing: returns the caller's tenant slug derived from the
     * JWT issuer's realm name (e.g. "t-app1" -> "app1"). Returns empty for
     * platform-realm JWTs or unknown realms.
     */
    @SuppressWarnings("unused")
    Optional<String> tenantSlugFromJwt(Jwt jwt) {
        if (jwt == null || jwt.getIssuer() == null) return Optional.empty();
        String issuer = jwt.getIssuer().toString();
        int idx = issuer.indexOf("/realms/");
        if (idx < 0) return Optional.empty();
        String realm = issuer.substring(idx + "/realms/".length());
        if (realm.endsWith("/")) realm = realm.substring(0, realm.length() - 1);
        if (!realm.startsWith(TENANT_REALM_PREFIX)) return Optional.empty();
        return tenantRepository.findByRealmNameAndDeletedAtIsNull(realm)
            .map(t -> t.getSlug());
    }
}
