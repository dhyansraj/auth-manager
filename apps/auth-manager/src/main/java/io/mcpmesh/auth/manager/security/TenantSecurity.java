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
        Jwt jwt = jwtAuth.getToken();

        var tenant = tenants.get(tenantId);  // throws TenantNotFoundException -> 404 (handled by GlobalExceptionHandler)

        String issuer = jwt.getIssuer() == null ? "" : jwt.getIssuer().toString();
        String expected = trim(keycloak.url()) + "/realms/" + tenant.getRealmName();
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
