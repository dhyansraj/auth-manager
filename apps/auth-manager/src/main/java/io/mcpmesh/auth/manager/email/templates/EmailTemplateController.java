package io.mcpmesh.auth.manager.email.templates;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.service.TenantService;
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
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

/**
 * REST endpoints for the per-tenant email-template lifecycle (slice 1).
 *
 * <pre>
 *   GET    /api/v1/tenants/{slug}/email-templates/starter   → starter zip download
 *   GET    /api/v1/tenants/{slug}/email-templates           → list stored types
 *   GET    /api/v1/tenants/{slug}/email-templates/{typeKey} → one stored template
 *   POST   /api/v1/tenants/{slug}/email-templates/{typeKey} → upload/replace (zip)
 *   PUT    /api/v1/tenants/{slug}/email-templates/{typeKey} → upload/replace (zip)
 *   DELETE /api/v1/tenants/{slug}/email-templates/{typeKey} → remove
 * </pre>
 *
 * Reads gate on {@code TENANT_VIEW}; mutations on {@code EMAIL_EDIT}.
 * The send API and admin-UI are deferred to later slices.
 */
@RestController
@RequestMapping("/api/v1/tenants/{slug}/email-templates")
public class EmailTemplateController {

    private final TenantService tenants;
    private final EmailTemplateService service;
    private final EmailTemplateZip zip;

    public EmailTemplateController(TenantService tenants,
                                   EmailTemplateService service,
                                   EmailTemplateZip zip) {
        this.tenants = tenants;
        this.service = service;
        this.zip = zip;
    }

    public record TemplateSummary(String typeKey, boolean hasAssets, Instant updatedAt) {}

    public record TemplateDetail(String typeKey, String htmlTemplate,
                                 String subjectTemplate, List<String> assetNames,
                                 Instant updatedAt) {}

    @GetMapping("/starter")
    @PreAuthorize("@perms.hasOnTenant(#slug, 'TENANT_VIEW')")
    public ResponseEntity<byte[]> starter(@PathVariable String slug) {
        tenants.getBySlug(slug);  // 404 for unknown slug
        byte[] body = zip.starterZip();
        return ResponseEntity.ok()
            .contentType(MediaType.valueOf("application/zip"))
            .header(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"t-" + slug + "-email-starter.zip\"")
            .body(body);
    }

    @GetMapping
    @PreAuthorize("@perms.hasOnTenant(#slug, 'TENANT_VIEW')")
    public List<TemplateSummary> list(@PathVariable String slug) {
        Tenant tenant = tenants.getBySlug(slug);
        return service.list(tenant.getId()).stream()
            .map(t -> new TemplateSummary(
                t.getTypeKey(),
                service.hasAssets(tenant.getId(), t.getTypeKey()),
                t.getUpdatedAt()))
            .toList();
    }

    @GetMapping("/{typeKey}")
    @PreAuthorize("@perms.hasOnTenant(#slug, 'TENANT_VIEW')")
    public TemplateDetail get(@PathVariable String slug, @PathVariable String typeKey) {
        Tenant tenant = tenants.getBySlug(slug);
        EmailTemplateService.requireValidTypeKey(typeKey);
        EmailTemplate t = service.get(tenant.getId(), typeKey)
            .orElseThrow(() -> new ResponseStatusException(
                HttpStatus.NOT_FOUND, "No email template for type: " + typeKey));
        List<String> names = service.assets(tenant.getId(), typeKey).stream()
            .map(TemplateAsset::name).toList();
        return new TemplateDetail(t.getTypeKey(), t.getHtmlTemplate(),
            t.getSubjectTemplate(), names, t.getUpdatedAt());
    }

    @PostMapping(path = "/{typeKey}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("@perms.hasOnTenant(#slug, 'EMAIL_EDIT')")
    public TemplateDetail upload(@PathVariable String slug,
                                 @PathVariable String typeKey,
                                 @RequestParam("file") MultipartFile file,
                                 Authentication auth) throws IOException {
        return doUpload(slug, typeKey, file, auth);
    }

    @PutMapping(path = "/{typeKey}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("@perms.hasOnTenant(#slug, 'EMAIL_EDIT')")
    public TemplateDetail replace(@PathVariable String slug,
                                  @PathVariable String typeKey,
                                  @RequestParam("file") MultipartFile file,
                                  Authentication auth) throws IOException {
        return doUpload(slug, typeKey, file, auth);
    }

    @DeleteMapping("/{typeKey}")
    @PreAuthorize("@perms.hasOnTenant(#slug, 'EMAIL_EDIT')")
    public ResponseEntity<Void> delete(@PathVariable String slug,
                                       @PathVariable String typeKey,
                                       Authentication auth) {
        Tenant tenant = tenants.getBySlug(slug);
        EmailTemplateService.requireValidTypeKey(typeKey);
        boolean removed = service.delete(tenant.getId(), typeKey, principal(auth));
        if (!removed) {
            throw new ResponseStatusException(
                HttpStatus.NOT_FOUND, "No email template for type: " + typeKey);
        }
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    private TemplateDetail doUpload(String slug, String typeKey, MultipartFile file,
                                    Authentication auth) throws IOException {
        Tenant tenant = tenants.getBySlug(slug);
        EmailTemplateService.requireValidTypeKey(typeKey);
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Multipart 'file' is required");
        }
        EmailTemplateZip.Parsed parsed = zip.parse(file.getBytes());
        EmailTemplate t = service.upsert(tenant.getId(), typeKey,
            parsed.html(), parsed.subject(), parsed.assets(), principal(auth));
        List<String> names = parsed.assets().stream().map(TemplateAsset::name).toList();
        return new TemplateDetail(t.getTypeKey(), t.getHtmlTemplate(),
            t.getSubjectTemplate(), names, t.getUpdatedAt());
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
