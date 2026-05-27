package io.mcpmesh.auth.manager.theme.branding;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.service.exception.TenantNotFoundException;
import io.mcpmesh.auth.manager.theme.ThemeApplier;
import io.mcpmesh.auth.manager.theme.ThemeStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Owns persistence + apply for tenant {@link BrandingConfig}. Mirror of
 * {@code RoutingConfigService}: Postgres source-of-truth + side-effecting
 * apply step (here, "rebuild the per-tenant theme ConfigMap with the new
 * branding overlay applied").
 *
 * <p>The flow on save:
 * <ol>
 *   <li>Persist {@code branding_config} JSONB on the tenant row.</li>
 *   <li>Read the tenant's existing theme files from the ConfigMap (if any).</li>
 *   <li>Run them through {@link BrandingMerger} with the new config.</li>
 *   <li>Write the merged file map back to the ConfigMap.</li>
 *   <li>Point the realm at {@code t-<slug>} and trigger a KC rollout.</li>
 * </ol>
 *
 * <p>Step 5 is what actually surfaces the new branding to end-users (KC reads
 * theme files at pod-start, so a rollout is unavoidable).
 */
@Service
public class BrandingService {

    private static final Logger log = LoggerFactory.getLogger(BrandingService.class);
    private static final ActorKind ACTOR_KIND = ActorKind.USER;

    private final TenantRepository tenants;
    private final ThemeStorage storage;
    private final ThemeApplier applier;
    private final BrandingMerger merger;
    private final AuditService audit;

    public BrandingService(
        TenantRepository tenants,
        ThemeStorage storage,
        ThemeApplier applier,
        BrandingMerger merger,
        AuditService audit
    ) {
        this.tenants = tenants;
        this.storage = storage;
        this.applier = applier;
        this.merger = merger;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public BrandingConfig get(String slug) {
        Tenant t = tenants.findBySlug(slug)
            .filter(x -> !x.isDeleted())
            .orElseThrow(() -> new TenantNotFoundException(slug));
        BrandingConfig cfg = t.getBrandingConfig();
        return cfg == null ? BrandingConfig.empty() : cfg;
    }

    /**
     * Replaces the tenant's BrandingConfig and re-applies the theme.
     * Returns the freshly-persisted config (validated + normalized).
     */
    @Transactional
    public BrandingConfig replace(String slug, BrandingConfig incoming, String actor) {
        Tenant t = tenants.findBySlug(slug)
            .filter(x -> !x.isDeleted())
            .orElseThrow(() -> new TenantNotFoundException(slug));

        BrandingConfig normalized = normalize(incoming);
        t.setBrandingConfig(normalized);
        tenants.save(t);

        try {
            reapply(slug, normalized, t);
        } catch (Exception e) {
            audit.recordFailure(actor, ACTOR_KIND, t.getId(),
                "branding.apply", "tenant", slug,
                Map.of("layoutVariant", normalized.layoutVariant()),
                e,
                Map.of("realm", String.valueOf(t.getRealmName())));
            throw new ResponseStatusException(
                org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR,
                "Branding apply failed: " + e.getMessage(), e);
        }

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("layoutVariant", normalized.layoutVariant());
        details.put("slotCount", normalized.slots() == null ? 0 : normalized.slots().size());
        details.put("realm", t.getRealmName());
        audit.recordSuccess(actor, ACTOR_KIND, t.getId(),
            "branding.apply", "tenant", slug, normalized, details);

        return normalized;
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    private static BrandingConfig normalize(BrandingConfig incoming) {
        if (incoming == null) return BrandingConfig.empty();
        String variant = incoming.layoutVariant();
        if (variant == null || !BrandingConfig.ALLOWED_LAYOUT_VARIANTS.contains(variant)) {
            throw new IllegalArgumentException(
                "layoutVariant must be one of " + BrandingConfig.ALLOWED_LAYOUT_VARIANTS
                + "; got '" + variant + "'");
        }
        Map<String, String> filteredSlots = new LinkedHashMap<>();
        if (incoming.slots() != null) {
            for (Map.Entry<String, String> e : incoming.slots().entrySet()) {
                if (BrandingConfig.ALLOWED_SLOT_NAMES.contains(e.getKey())) {
                    filteredSlots.put(e.getKey(), e.getValue() == null ? "" : e.getValue());
                }
            }
        }
        return new BrandingConfig(variant, filteredSlots);
    }

    /**
     * Re-materializes the tenant ConfigMap with branding overlays applied.
     * Reads the current ConfigMap files (if any), merges, writes back, then
     * points the realm at {@code t-<slug>} and triggers a rollout.
     */
    private void reapply(String slug, BrandingConfig config, Tenant tenant) {
        Optional<Map<String, byte[]>> existingFiles = storage.readThemeFiles(slug);
        Map<String, byte[]> base = existingFiles.orElseGet(Map::of);
        Map<String, byte[]> merged = merger.merge(base, config);

        if (merged.isEmpty()) {
            // Truly empty config + no existing zip. Nothing to write; reset
            // the realm theme so KC falls back to default.
            log.info("Branding for slug={} is empty and no existing theme; clearing realm theme", slug);
            applier.applyTheme(tenant.getRealmName(), null);
            return;
        }

        storage.saveTheme(slug, merged);
        applier.applyTheme(tenant.getRealmName(), "t-" + slug);
    }
}
