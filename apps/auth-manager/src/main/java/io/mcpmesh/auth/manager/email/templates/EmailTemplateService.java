package io.mcpmesh.auth.manager.email.templates;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * CRUD + resolution for per-tenant transactional email templates.
 *
 * <p>{@link #resolve(Tenant, String)} is the seam the render pipeline calls:
 * it returns the tenant's stored override when present, and for the reserved
 * {@code invitation} key falls back to the phase-1 classpath default
 * ({@code email-templates/invitation.html.mustache}, no assets). Any other
 * unknown key with no stored row resolves to {@link Optional#empty()} so the
 * caller can 404 / skip.
 */
@Service
public class EmailTemplateService {

    private static final Logger log = LoggerFactory.getLogger(EmailTemplateService.class);
    private static final ActorKind ACTOR_KIND = ActorKind.USER;

    /** Reserved key whose absence falls back to the bundled invitation template. */
    public static final String INVITATION_KEY = "invitation";
    private static final String DEFAULT_INVITATION_RESOURCE =
        "email-templates/invitation.html.mustache";

    private static final Pattern TYPE_KEY = Pattern.compile("[a-z0-9-]{1,64}");

    private final EmailTemplateRepository templateRepo;
    private final EmailTemplateAssetRepository assetRepo;
    private final AuditService audit;

    public EmailTemplateService(EmailTemplateRepository templateRepo,
                                EmailTemplateAssetRepository assetRepo,
                                AuditService audit) {
        this.templateRepo = templateRepo;
        this.assetRepo = assetRepo;
        this.audit = audit;
    }

    // -- validation -----------------------------------------------------------

    /** Validates the slug shape; throws {@link IllegalArgumentException} if invalid. */
    public static String requireValidTypeKey(String typeKey) {
        if (typeKey == null || !TYPE_KEY.matcher(typeKey).matches()) {
            throw new IllegalArgumentException(
                "type_key must match [a-z0-9-]{1,64}; got: " + typeKey);
        }
        return typeKey;
    }

    // -- CRUD -----------------------------------------------------------------

    @Transactional
    public EmailTemplate upsert(UUID tenantId, String typeKey, String htmlTemplate,
                                String subjectTemplate, List<TemplateAsset> assets,
                                String actor) {
        requireValidTypeKey(typeKey);
        if (htmlTemplate == null || htmlTemplate.isBlank()) {
            throw new IllegalArgumentException("htmlTemplate is required");
        }

        EmailTemplate tpl = templateRepo.findByTenantIdAndTypeKey(tenantId, typeKey)
            .map(existing -> {
                existing.update(htmlTemplate, subjectTemplate);
                return existing;
            })
            .orElseGet(() -> new EmailTemplate(tenantId, typeKey, htmlTemplate, subjectTemplate));
        tpl = templateRepo.saveAndFlush(tpl);

        // Replace the asset set wholesale: drop existing rows, then re-insert.
        assetRepo.deleteByTenantIdAndTypeKey(tenantId, typeKey);
        assetRepo.flush();
        int assetCount = 0;
        if (assets != null) {
            for (TemplateAsset a : assets) {
                assetRepo.save(new EmailTemplateAsset(
                    tenantId, typeKey, a.name(), a.contentType(), a.bytes()));
                assetCount++;
            }
        }

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("typeKey", typeKey);
        details.put("htmlBytes", htmlTemplate.getBytes(StandardCharsets.UTF_8).length);
        details.put("hasSubject", subjectTemplate != null && !subjectTemplate.isBlank());
        details.put("assetCount", assetCount);
        audit.recordSuccess(actor, ACTOR_KIND, tenantId,
            "email_template.upsert", "email_template", typeKey, null, details);

        return tpl;
    }

    @Transactional(readOnly = true)
    public Optional<EmailTemplate> get(UUID tenantId, String typeKey) {
        return templateRepo.findByTenantIdAndTypeKey(tenantId, typeKey);
    }

    @Transactional(readOnly = true)
    public List<TemplateAsset> assets(UUID tenantId, String typeKey) {
        List<TemplateAsset> out = new ArrayList<>();
        for (EmailTemplateAsset a : assetRepo.findByTenantIdAndTypeKeyOrderByNameAsc(tenantId, typeKey)) {
            out.add(new TemplateAsset(a.getName(), a.getContentType(), a.getBytes()));
        }
        return out;
    }

    @Transactional(readOnly = true)
    public List<EmailTemplate> list(UUID tenantId) {
        return templateRepo.findByTenantIdOrderByTypeKeyAsc(tenantId);
    }

    @Transactional(readOnly = true)
    public boolean hasAssets(UUID tenantId, String typeKey) {
        return !assetRepo.findByTenantIdAndTypeKeyOrderByNameAsc(tenantId, typeKey).isEmpty();
    }

    @Transactional
    public boolean delete(UUID tenantId, String typeKey, String actor) {
        requireValidTypeKey(typeKey);
        Optional<EmailTemplate> existing = templateRepo.findByTenantIdAndTypeKey(tenantId, typeKey);
        if (existing.isEmpty()) {
            return false;
        }
        // Assets cascade via the composite FK, but delete explicitly so the
        // ORM-managed rows are cleared deterministically within this tx.
        assetRepo.deleteByTenantIdAndTypeKey(tenantId, typeKey);
        templateRepo.deleteByTenantIdAndTypeKey(tenantId, typeKey);
        audit.recordSuccess(actor, ACTOR_KIND, tenantId,
            "email_template.delete", "email_template", typeKey, null,
            Map.of("typeKey", typeKey));
        return true;
    }

    // -- resolution -----------------------------------------------------------

    /**
     * Returns the effective template for the render pipeline: the tenant's
     * stored override if present, else the classpath default for
     * {@code invitation} only, else {@link Optional#empty()}.
     */
    @Transactional(readOnly = true)
    public Optional<ResolvedTemplate> resolve(Tenant tenant, String typeKey) {
        requireValidTypeKey(typeKey);
        Optional<EmailTemplate> stored = templateRepo.findByTenantIdAndTypeKey(tenant.getId(), typeKey);
        if (stored.isPresent()) {
            EmailTemplate t = stored.get();
            return Optional.of(new ResolvedTemplate(
                typeKey, t.getHtmlTemplate(), t.getSubjectTemplate(),
                assets(tenant.getId(), typeKey), true));
        }
        if (INVITATION_KEY.equals(typeKey)) {
            return Optional.of(new ResolvedTemplate(
                typeKey, loadClasspathInvitation(), null, List.of(), false));
        }
        return Optional.empty();
    }

    private String loadClasspathInvitation() {
        ClassPathResource res = new ClassPathResource(DEFAULT_INVITATION_RESOURCE);
        try (InputStream in = res.getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("Failed to load default invitation template {}", DEFAULT_INVITATION_RESOURCE, e);
            throw new IllegalStateException(
                "Default invitation template missing: " + DEFAULT_INVITATION_RESOURCE, e);
        }
    }
}
