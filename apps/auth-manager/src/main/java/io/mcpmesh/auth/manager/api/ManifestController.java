package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.api.dto.AccessManifest;
import io.mcpmesh.auth.manager.api.dto.AppManifestResponse;
import io.mcpmesh.auth.manager.service.ManifestService;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * Per-app access-manifest endpoints. Guards mirror the sibling
 * {@link AppController} (whole {@code /apps/**} surface gates on
 * {@code APPS_EDIT} for reads) plus the catalog's dedicated
 * {@code MANIFEST_APPLY} perm for the apply write — both are in the
 * tenant-admin bundle, and platform-admin bypasses via
 * {@code @perms.hasOnTenantId}.
 */
@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/apps/{appId}/manifests")
public class ManifestController {

    private final ManifestService service;

    public ManifestController(ManifestService service) {
        this.service = service;
    }

    @PostMapping("/apply")
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'MANIFEST_APPLY')")
    public AppManifestResponse apply(
        @PathVariable UUID tenantId,
        @PathVariable UUID appId,
        @Valid @RequestBody AccessManifest manifest,
        Authentication auth
    ) {
        var result = service.apply(tenantId, appId, manifest, principal(auth));
        return AppManifestResponse.from(result.manifest(), result.noOp());
    }

    @GetMapping
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'APPS_EDIT')")
    public List<AppManifestResponse> list(@PathVariable UUID tenantId, @PathVariable UUID appId) {
        return service.listForApp(tenantId, appId).stream()
            .map(m -> AppManifestResponse.from(m, false))
            .toList();
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
