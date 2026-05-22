package io.mcpmesh.auth.manager.theme;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.service.TenantService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Orchestrates the upload → validate → store → apply pipeline for tenant
 * themes. Owns the audit emission so the controller stays thin.
 */
@Service
public class ThemeService {

    private static final Logger log = LoggerFactory.getLogger(ThemeService.class);
    private static final ActorKind ACTOR_KIND = ActorKind.USER;

    private final TenantService tenants;
    private final ThemeValidator validator;
    private final ThemeStorage storage;
    private final ThemeApplier applier;
    private final AuditService audit;

    public ThemeService(TenantService tenants,
                        ThemeValidator validator,
                        ThemeStorage storage,
                        ThemeApplier applier,
                        AuditService audit) {
        this.tenants = tenants;
        this.validator = validator;
        this.storage = storage;
        this.applier = applier;
        this.audit = audit;
    }

    /** Reads the canned starter theme from classpath and returns it as a zip. */
    public byte[] starterZip(String slug) {
        // The starter is generic: identical bytes for every tenant. The slug
        // is only used to name the suggested download file, which is set in
        // the Content-Disposition header by the controller.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(out)) {
            addStarterEntries(zos);
        } catch (IOException e) {
            throw new RuntimeException("Failed to assemble starter zip", e);
        }
        log.debug("Built starter zip for slug={} ({} bytes)", slug, out.size());
        return out.toByteArray();
    }

    private void addStarterEntries(ZipOutputStream zos) throws IOException {
        // Resource paths under /themes/starter/. The list is intentionally
        // small; tenant admins add their own files via the upload flow.
        List<String> resources = List.of(
            "theme.properties",
            "resources/css/custom.css",
            "resources/img/logo.svg",
            "messages/messages_en.properties",
            "README.md"
        );
        for (String name : resources) {
            ClassPathResource cp = new ClassPathResource("themes/starter/" + name);
            if (!cp.exists()) {
                log.warn("Starter resource missing: themes/starter/{}", name);
                continue;
            }
            zos.putNextEntry(new ZipEntry(name));
            try (InputStream in = cp.getInputStream()) {
                in.transferTo(zos);
            }
            zos.closeEntry();
        }
    }

    public ThemeMeta upload(String slug, byte[] zipBytes, String actor) {
        Tenant tenant = tenants.getBySlug(slug);
        ValidationResult vr = validator.validateZip(zipBytes);
        UUID tenantId = tenant.getId();

        if (!vr.isValid()) {
            audit.recordFailure(actor, ACTOR_KIND, tenantId,
                "theme.upload", "theme", tenant.getSlug(),
                Map.of("byteCount", zipBytes == null ? 0 : zipBytes.length),
                new RuntimeException("validation_failed"),
                Map.of(
                    "errorCount", vr.errors().size(),
                    "firstError", vr.errors().get(0).code()
                ));
            throw new ThemeValidationException(vr.errors());
        }

        try {
            storage.saveTheme(slug, vr.extractedFiles());
            applier.applyTheme(tenant.getRealmName(), "t-" + slug);
        } catch (Exception e) {
            audit.recordFailure(actor, ACTOR_KIND, tenantId,
                "theme.apply", "theme", tenant.getSlug(),
                Map.of("fileCount", vr.extractedFiles().size()),
                e,
                Map.of("realm", tenant.getRealmName()));
            throw new ResponseStatusException(
                org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR,
                "Theme apply failed: " + e.getMessage(), e);
        }

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("fileCount", vr.extractedFiles().size());
        details.put("totalBytes", vr.extractedFiles().values().stream()
            .mapToLong(arr -> arr.length).sum());
        details.put("realm", tenant.getRealmName());

        audit.recordSuccess(actor, ACTOR_KIND, tenantId,
            "theme.upload", "theme", tenant.getSlug(),
            Map.of("byteCount", zipBytes.length),
            details);
        audit.recordSuccess(actor, ACTOR_KIND, tenantId,
            "theme.apply", "theme", tenant.getSlug(),
            null, details);

        return storage.getTheme(slug).orElse(ThemeMeta.absent());
    }

    public ThemeMeta currentMeta(String slug) {
        // Resolve tenant first so callers get 404 (not 403→meta) for non-existent slug.
        tenants.getBySlug(slug);
        Optional<ThemeMeta> meta = storage.getTheme(slug);
        return meta.orElse(ThemeMeta.absent());
    }

    public void delete(String slug, String actor) {
        Tenant tenant = tenants.getBySlug(slug);
        boolean removed = storage.deleteTheme(slug);
        try {
            // Reset realm to default theme (null clears the field).
            applier.applyTheme(tenant.getRealmName(), null);
        } catch (Exception e) {
            audit.recordFailure(actor, ACTOR_KIND, tenant.getId(),
                "theme.delete", "theme", tenant.getSlug(), null, e,
                Map.of("removed", removed, "realm", tenant.getRealmName()));
            throw new ResponseStatusException(
                org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR,
                "Theme delete partial-failed at apply: " + e.getMessage(), e);
        }
        audit.recordSuccess(actor, ACTOR_KIND, tenant.getId(),
            "theme.delete", "theme", tenant.getSlug(), null,
            Map.of("removed", removed, "realm", tenant.getRealmName()));
    }

    public RolloutStatus status(String slug) {
        tenants.getBySlug(slug);  // 404 if unknown
        return applier.getRolloutStatus();
    }

    public byte[] suggestedStarterFilename(String slug) {
        // helper exposed only because controllers prefer pure-data helpers
        return ("t-" + slug + "-starter.zip").getBytes(StandardCharsets.UTF_8);
    }
}
