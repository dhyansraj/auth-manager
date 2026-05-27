package io.mcpmesh.auth.manager.theme.branding;

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

/**
 * REST endpoints for the per-tenant rich-login branding config (layout
 * variant + named slot HTML).
 *
 * <pre>
 *   GET /api/v1/tenants/{slug}/branding   → BrandingConfig (or empty default)
 *   PUT /api/v1/tenants/{slug}/branding   → upsert + reapply theme
 * </pre>
 *
 * Sibling of {@link io.mcpmesh.auth.manager.theme.ThemeController}; uses the
 * same {@code BRANDING_EDIT}/{@code TENANT_VIEW} permission split.
 */
@RestController
@RequestMapping("/api/v1/tenants/{slug}/branding")
public class BrandingController {

    private final BrandingService service;

    public BrandingController(BrandingService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize("@perms.hasOnTenant(#slug, 'TENANT_VIEW')")
    public BrandingConfig get(@PathVariable String slug) {
        return service.get(slug);
    }

    @PutMapping
    @PreAuthorize("@perms.hasOnTenant(#slug, 'BRANDING_EDIT')")
    public BrandingConfig replace(
        @PathVariable String slug,
        @RequestBody BrandingConfig body,
        Authentication auth
    ) {
        return service.replace(slug, body, principal(auth));
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
