package io.mcpmesh.auth.manager.authflow;

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

import java.util.Map;
import java.util.UUID;

/**
 * Per-tenant login-method config endpoints.
 *
 * <pre>
 *   GET /api/v1/tenants/{tenantId}/login-methods            → LoginMethodStatus
 *   PUT /api/v1/tenants/{tenantId}/login-methods/password   body: { enabled: boolean }
 * </pre>
 *
 * <p>Guards: read on {@code TENANT_VIEW}, write on {@code TENANT_EDIT}.
 */
@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/login-methods")
public class LoginMethodController {

    private final LoginMethodService service;

    public LoginMethodController(LoginMethodService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'TENANT_VIEW')")
    public LoginMethodStatus get(@PathVariable UUID tenantId) {
        return service.get(tenantId);
    }

    @PutMapping("/password")
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'TENANT_EDIT')")
    public LoginMethodStatus setPasswordEnabled(
        @PathVariable UUID tenantId,
        @RequestBody Map<String, Boolean> body,
        Authentication auth
    ) {
        Boolean enabled = body == null ? null : body.get("enabled");
        if (enabled == null) {
            throw new org.springframework.web.server.ResponseStatusException(
                org.springframework.http.HttpStatus.BAD_REQUEST,
                "login_methods.enabled_required: body must include 'enabled' boolean");
        }
        return service.setPasswordEnabled(tenantId, enabled, principal(auth));
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
