package io.mcpmesh.auth.manager.security;

import io.mcpmesh.auth.manager.keycloak.KeycloakProperties;
import io.mcpmesh.auth.manager.service.TenantService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Exposed as the SpEL bean {@code tenantSecurity} so controllers can write:
 * {@code @PreAuthorize("@tenantSecurity.hasRole(#tenantId, 'tenant-admin')")}
 *
 * <p>Verifies (a) the caller has a JWT, (b) that JWT was issued by the
 * target tenant's realm, and (c) the JWT's {@code resource_access.usermanagement.roles}
 * claim contains the named role.
 */
@Component("tenantSecurity")
public class TenantSecurity {

    private static final Logger log = LoggerFactory.getLogger(TenantSecurity.class);
    private static final String USERMANAGEMENT_CLIENT = "usermanagement";

    private final TenantService tenants;
    private final KeycloakProperties keycloak;

    public TenantSecurity(TenantService tenants, KeycloakProperties keycloak) {
        this.tenants = tenants;
        this.keycloak = keycloak;
    }

    public boolean hasRole(UUID tenantId, String roleName) {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (!(auth instanceof JwtAuthenticationToken jwtAuth)) {
            log.debug("hasRole({},{}): no JWT in context", tenantId, roleName);
            return false;
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
        var tenant = tenants.getBySlug(slug);
        return checkRoleClaim(jwtAuth.getToken(), tenant.getRealmName(), roleName);
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
