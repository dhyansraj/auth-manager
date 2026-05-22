package io.mcpmesh.auth.manager.theme;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

/**
 * REST endpoints for the per-tenant theme lifecycle.
 *
 * <pre>
 *   GET    /api/v1/tenants/{slug}/theme/starter  → zip download
 *   POST   /api/v1/tenants/{slug}/theme          → upload + apply
 *   GET    /api/v1/tenants/{slug}/theme          → metadata
 *   DELETE /api/v1/tenants/{slug}/theme          → reset to default
 *   GET    /api/v1/tenants/{slug}/theme/status   → rollout status
 * </pre>
 *
 * <p>Reads are gated by {@code canSeeTenantBySlug}; mutations require
 * {@code canManageTenant} (tenant-admin or platform-admin).
 */
@RestController
@RequestMapping("/api/v1/tenants/{slug}/theme")
public class ThemeController {

    private final ThemeService service;

    public ThemeController(ThemeService service) {
        this.service = service;
    }

    @GetMapping("/starter")
    @PreAuthorize("@tenantSecurity.canSeeTenantBySlug(#slug)")
    public ResponseEntity<byte[]> starter(@PathVariable String slug) {
        byte[] zip = service.starterZip(slug);
        return ResponseEntity.ok()
            .contentType(MediaType.valueOf("application/zip"))
            .header(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"t-" + slug + "-starter.zip\"")
            .body(zip);
    }

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("@tenantSecurity.canManageTenant(#slug)")
    public ThemeMeta upload(
        @PathVariable String slug,
        @RequestParam("file") MultipartFile file,
        Authentication auth
    ) throws IOException {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Multipart 'file' is required");
        }
        return service.upload(slug, file.getBytes(), principal(auth));
    }

    @GetMapping
    @PreAuthorize("@tenantSecurity.canSeeTenantBySlug(#slug)")
    public ThemeMeta get(@PathVariable String slug) {
        return service.currentMeta(slug);
    }

    @DeleteMapping
    @PreAuthorize("@tenantSecurity.canManageTenant(#slug)")
    public ResponseEntity<Void> delete(@PathVariable String slug, Authentication auth) {
        service.delete(slug, principal(auth));
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @GetMapping("/status")
    @PreAuthorize("@tenantSecurity.canSeeTenantBySlug(#slug)")
    public RolloutStatus status(@PathVariable String slug) {
        return service.status(slug);
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
