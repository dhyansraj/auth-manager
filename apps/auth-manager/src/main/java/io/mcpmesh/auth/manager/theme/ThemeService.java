package io.mcpmesh.auth.manager.theme;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.service.TenantService;
import io.mcpmesh.auth.manager.theme.branding.BrandingConfig;
import io.mcpmesh.auth.manager.theme.branding.BrandingMerger;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
    private final TenantRepository tenantRepo;
    private final ThemeValidator validator;
    private final ThemeStorage storage;
    private final ThemeApplier applier;
    private final BrandingMerger brandingMerger;
    private final AuditService audit;

    public ThemeService(TenantService tenants,
                        TenantRepository tenantRepo,
                        ThemeValidator validator,
                        ThemeStorage storage,
                        ThemeApplier applier,
                        BrandingMerger brandingMerger,
                        AuditService audit) {
        this.tenants = tenants;
        this.tenantRepo = tenantRepo;
        this.validator = validator;
        this.storage = storage;
        this.applier = applier;
        this.brandingMerger = brandingMerger;
        this.audit = audit;
    }

    /**
     * Reads the canned starter theme from classpath, layout-aware: the
     * {@code login/theme.properties}, {@code login/messages/messages_en.properties},
     * {@code login/resources/css/custom.css}, and {@code README.md} entries
     * are customised for the tenant's currently-configured layout variant
     * (default {@code centered}). Other entries (account/, email/, logo.svg)
     * are passed through as-is from the classpath.
     */
    public byte[] starterZip(String slug) {
        // Resolve the tenant's current layout variant so the starter ships
        // placeholder slot blocks only for the slots visible in that layout.
        // Defensive: if tenant lookup fails (e.g. unit tests with mocked
        // collaborators), fall back to "centered".
        String variant = BrandingConfig.DEFAULT_LAYOUT_VARIANT;
        try {
            Tenant tenant = tenants.getBySlug(slug);
            if (tenant != null) {
                BrandingConfig cfg = tenant.getBrandingConfig();
                if (cfg != null && cfg.layoutVariant() != null
                    && BrandingConfig.ALLOWED_LAYOUT_VARIANTS.contains(cfg.layoutVariant())) {
                    variant = cfg.layoutVariant();
                }
            }
        } catch (Exception e) {
            log.debug("starterZip: tenant lookup failed for slug={}, defaulting to centered", slug);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(out)) {
            addStarterEntries(zos, variant);
        } catch (IOException e) {
            throw new RuntimeException("Failed to assemble starter zip", e);
        }
        log.debug("Built starter zip for slug={} variant={} ({} bytes)", slug, variant, out.size());
        return out.toByteArray();
    }

    private void addStarterEntries(ZipOutputStream zos, String variant) throws IOException {
        // Keycloak themes require a <type>/ subdirectory layout (login, account,
        // email, ...).
        //
        // Three entries are layout-aware (generated dynamically):
        //   - login/theme.properties              (parent=mcpmesh.flexible)
        //   - login/messages/messages_en.properties (mcpLayoutVariant + slot placeholders)
        //   - login/resources/css/custom.css      (slot-styling header comment)
        //   - README.md                            (layout-specific instructions)
        //
        // Everything else is passed through verbatim from the classpath.
        Map<String, byte[]> dynamic = new LinkedHashMap<>();
        dynamic.put("login/theme.properties",
            buildLoginThemeProperties().getBytes(StandardCharsets.UTF_8));
        dynamic.put("login/messages/messages_en.properties",
            buildLoginMessagesProperties(variant).getBytes(StandardCharsets.UTF_8));
        dynamic.put("login/resources/css/custom.css",
            buildLoginCustomCss().getBytes(StandardCharsets.UTF_8));
        dynamic.put("README.md",
            buildStarterReadme(variant).getBytes(StandardCharsets.UTF_8));

        // Classpath-backed entries. Order matters only for human inspection of
        // the resulting zip; LinkedHashMap preserves insertion order.
        List<String> classpathResources = List.of(
            "login/resources/img/logo.svg",
            "account/theme.properties",
            "account/resources/css/custom.css",
            "account/resources/img/logo.svg",
            "email/theme.properties",
            "email/messages/messages_en.properties"
        );

        // Write dynamic entries first (login/* lives here for the most part).
        for (Map.Entry<String, byte[]> e : dynamic.entrySet()) {
            zos.putNextEntry(new ZipEntry(e.getKey()));
            zos.write(e.getValue());
            zos.closeEntry();
        }

        for (String name : classpathResources) {
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

    // -------------------------------------------------------------------------
    // Layout-aware starter content builders
    // -------------------------------------------------------------------------

    /**
     * login/theme.properties always pins parent=mcpmesh.flexible. The starter
     * is meant for tenants on the flexible parent theme; pinning here means a
     * round-trip (download → re-upload, no edits) doesn't change the parent.
     */
    static String buildLoginThemeProperties() {
        return "parent=mcpmesh-flexible\n"
            + "import=common/keycloak\n"
            + "styles=css/custom.css\n";
    }

    /**
     * login/messages/messages_en.properties: base message-override examples
     * + mcpLayoutVariant=&lt;variant&gt; + one commented placeholder block per
     * slot that is visible in the chosen layout.
     */
    static String buildLoginMessagesProperties(String variant) {
        StringBuilder out = new StringBuilder();
        out.append("# Login page text overrides. Uncomment + change to customize.\n");
        out.append("# Only override what you want to change; everything else inherits from\n");
        out.append("# the parent theme's catalog.\n");
        out.append("#\n");
        out.append("# See the full KC message catalog at:\n");
        out.append("# https://github.com/keycloak/keycloak/blob/main/themes/src/main/resources/theme/base/login/messages/messages_en.properties\n");
        out.append("\n");
        out.append("# loginTitle=Welcome\n");
        out.append("# loginAccountTitle=Sign in to your account\n");
        out.append("# loginTitleHtml=Welcome to <strong>Your Brand</strong>\n");
        out.append("# doLogIn=Continue\n");
        out.append("# doSignUp=Get started\n");
        out.append("# emailInstruction=Enter the email address associated with your account\n");
        out.append("# rememberMe=Stay signed in\n");
        out.append("# doForgotPassword=Forgot password?\n");
        out.append("# noAccount=Don't have an account?\n");
        out.append("# doRegister=Create one\n");
        out.append("# identity-provider-login-label=Or continue with\n");
        out.append("\n");
        out.append("# =======================================================================\n");
        out.append("# mcpmesh.flexible layout variant\n");
        out.append("# =======================================================================\n");
        out.append("# Selects one of the platform-managed CSS grid templates. Allowed values:\n");
        out.append("#   centered     - single-column, login card centered\n");
        out.append("#   split-left   - marketing column on the left, login card on the right\n");
        out.append("#   split-right  - login card on the left, marketing column on the right\n");
        out.append("#   bleed        - full-bleed background, login card floats over it\n");
        out.append("#\n");
        out.append("# This value mirrors the dropdown in the admin-ui Branding tab; on upload\n");
        out.append("# the value here wins (the dropdown gets updated to match).\n");
        out.append("mcpLayoutVariant=").append(variant).append('\n');
        out.append("\n");

        for (SlotPlaceholder slot : visibleSlotsForLayout(variant)) {
            out.append(slot.render());
        }

        return out.toString();
    }

    /**
     * Returns the placeholder definitions for slots visible in the given
     * layout variant, in display order. Unknown variants fall back to centered.
     */
    private static List<SlotPlaceholder> visibleSlotsForLayout(String variant) {
        return switch (variant) {
            case "split-left" -> List.of(
                SlotPlaceholder.MARKETING_LEFT,
                SlotPlaceholder.ABOVE_FORM,
                SlotPlaceholder.BELOW_FORM,
                SlotPlaceholder.FOOTER
            );
            case "split-right" -> List.of(
                SlotPlaceholder.MARKETING_RIGHT,
                SlotPlaceholder.ABOVE_FORM,
                SlotPlaceholder.BELOW_FORM,
                SlotPlaceholder.FOOTER
            );
            case "bleed" -> List.of(SlotPlaceholder.FOOTER);
            default /* centered */ -> List.of(
                SlotPlaceholder.ABOVE_FORM,
                SlotPlaceholder.BELOW_FORM,
                SlotPlaceholder.FOOTER
            );
        };
    }

    /**
     * Definitions for the slot placeholder blocks emitted into the starter's
     * messages_en.properties. Each enum value owns its own description so the
     * builder above stays a thin loop.
     */
    private enum SlotPlaceholder {
        MARKETING_LEFT(
            "marketing-left", "mcpmeshSlotMarketingLeftHtml",
            "Shown in the left column of the split-left layout. Best for:",
            List.of("Product taglines, feature lists",
                    "Trust badges / customer logos",
                    "Brand storytelling"),
            "<div class=\"mcp-marketing\"><h2>Welcome</h2><p>Your tagline here.</p></div>"
        ),
        MARKETING_RIGHT(
            "marketing-right", "mcpmeshSlotMarketingRightHtml",
            "Shown in the right column of the split-right layout. Best for:",
            List.of("Product taglines, feature lists",
                    "Trust badges / customer logos",
                    "Brand storytelling"),
            "<div class=\"mcp-marketing\"><h2>Welcome</h2><p>Your tagline here.</p></div>"
        ),
        ABOVE_FORM(
            "above-form", "mcpmeshSlotAboveFormHtml",
            "Renders directly above the login form, inside the card. Best for:",
            List.of("Brand wordmark / logo line",
                    "Short tagline above the email field",
                    "Beta / staging environment banners"),
            "<div class=\"mcp-above-form\"><strong>Sign in to Acme</strong></div>"
        ),
        BELOW_FORM(
            "below-form", "mcpmeshSlotBelowFormHtml",
            "Renders directly below the login form, inside the card. Best for:",
            List.of("Terms-of-service / privacy-policy links",
                    "Support contact info",
                    "Compliance disclosures"),
            "<div class=\"mcp-below-form\"><a href=\"/terms\">Terms</a> &middot; <a href=\"/privacy\">Privacy</a></div>"
        ),
        FOOTER(
            "footer", "mcpmeshSlotFooterHtml",
            "Renders below the card, full-page width. Best for:",
            List.of("Copyright lines",
                    "Address / legal entity",
                    "Help-center / contact links"),
            "<footer class=\"mcp-footer\"><p>&copy; 2026 Acme, Inc.</p></footer>"
        );

        final String displayName;
        final String key;
        final String purpose;
        final List<String> uses;
        final String exampleHtml;

        SlotPlaceholder(String displayName, String key, String purpose,
                        List<String> uses, String exampleHtml) {
            this.displayName = displayName;
            this.key = key;
            this.purpose = purpose;
            this.uses = uses;
            this.exampleHtml = exampleHtml;
        }

        /** Renders this slot's commented placeholder block. */
        String render() {
            StringBuilder b = new StringBuilder();
            b.append("# === Slot: ").append(displayName).append(' ');
            // Pad the banner to ~72 chars for a tidy ruler.
            int padding = Math.max(3, 60 - displayName.length());
            for (int i = 0; i < padding; i++) b.append('=');
            b.append('\n');
            b.append("# ").append(purpose).append('\n');
            for (String use : uses) {
                b.append("#   - ").append(use).append('\n');
            }
            b.append("# HTML allowed. No executable tags, no event handlers, no\n");
            b.append("# JS-protocol URLs. Sanitized server-side on upload.\n");
            b.append("#\n");
            b.append("# To USE this slot, uncomment the key below and replace the example\n");
            b.append("# with your own HTML. To DISABLE the slot, delete or leave the key\n");
            b.append("# commented.\n");
            b.append("#\n");
            b.append("# Multi-line values: end intermediate lines with a backslash, or write\n");
            b.append("# the entire HTML on one logical line (java.util.Properties format).\n");
            b.append("#\n");
            b.append("# ").append(key).append('=').append(exampleHtml).append('\n');
            b.append("\n");
            return b.toString();
        }
    }

    /**
     * Prepends a comment block to the canned custom.css describing the
     * {@code .mcp-slot-*} hooks the flexible parent theme exposes for
     * fine-tuning per-slot styling.
     */
    static String buildLoginCustomCss() {
        ClassPathResource cp = new ClassPathResource("themes/starter/login/resources/css/custom.css");
        String body;
        try (InputStream in = cp.getInputStream()) {
            body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read starter login custom.css", e);
        }
        String header = ""
            + "/* =======================================================================\n"
            + " * mcpmesh.flexible slot-styling hooks\n"
            + " * =======================================================================\n"
            + " *\n"
            + " * The parent theme wraps each visible slot in a class so you can target\n"
            + " * just that slot from this CSS file. Layout-specific wrappers are also\n"
            + " * exposed for grid-aware tweaks.\n"
            + " *\n"
            + " *   .mcp-layout-centered            Page wrapper for the centered layout\n"
            + " *   .mcp-layout-split-left          Page wrapper for the split-left layout\n"
            + " *   .mcp-layout-split-right         Page wrapper for the split-right layout\n"
            + " *   .mcp-layout-bleed               Page wrapper for the full-bleed layout\n"
            + " *\n"
            + " *   .mcp-slot-marketing-left        Slot wrapper (split-left only)\n"
            + " *   .mcp-slot-marketing-right       Slot wrapper (split-right only)\n"
            + " *   .mcp-slot-above-form            Slot wrapper, inside the card\n"
            + " *   .mcp-slot-below-form            Slot wrapper, inside the card\n"
            + " *   .mcp-slot-footer                Slot wrapper, below the card\n"
            + " *\n"
            + " * Example: tighten footer text to a single muted line:\n"
            + " *   .mcp-slot-footer { color: var(--kc-text-muted); font-size: 0.85rem; }\n"
            + " * ======================================================================= */\n"
            + "\n";
        return header + body;
    }

    /** Layout-aware README dropped at the zip root for unzip-time guidance. */
    static String buildStarterReadme(String variant) {
        String layoutLabel = switch (variant) {
            case "split-left" -> "split-left";
            case "split-right" -> "split-right";
            case "bleed" -> "full-bleed";
            default -> "centered";
        };
        return ""
            + "# mcpmesh.flexible starter - " + layoutLabel + " layout\n"
            + "\n"
            + "Your tenant is configured with the **" + layoutLabel + "** layout. This starter\n"
            + "zip contains placeholder content for the slots that are visible in this\n"
            + "layout.\n"
            + "\n"
            + "## What to edit\n"
            + "\n"
            + "1. `login/messages/messages_en.properties` - slot HTML (uncomment keys you\n"
            + "   want, paste your content)\n"
            + "2. `login/resources/css/custom.css` - colors, fonts, brand polish\n"
            + "3. `login/resources/img/logo.svg` - your logo\n"
            + "\n"
            + "## What NOT to edit\n"
            + "\n"
            + "- `login/theme.properties` - leaves parent set to mcpmesh.flexible (don't\n"
            + "  change)\n"
            + "- The slot key names - must match exactly what the platform's parent theme\n"
            + "  expects\n"
            + "\n"
            + "## Upload\n"
            + "\n"
            + "Zip the contents (NOT the parent dir), upload via the Branding tab. The\n"
            + "platform will sanitize HTML, validate, and apply.\n"
            + "\n"
            + "## To change layout later\n"
            + "\n"
            + "Change the layout dropdown in the Branding tab. Re-download the starter\n"
            + "to get fresh placeholders for the new layout's slot set.\n";
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

        // MVP: if the uploaded zip declares an mcpLayoutVariant, reconcile the
        // tenant's BrandingConfig.layoutVariant so the dropdown stays in sync
        // with what the operator just shipped. Slots are NOT extracted; they
        // live entirely in the zip (re-downloads always emit fresh generic
        // placeholders, not the operator's prior content).
        BrandingConfig branding = tenant.getBrandingConfig();
        BrandingConfig effective = reconcileLayoutFromZip(vr.extractedFiles(), branding);
        if (effective != branding) {
            tenant.setBrandingConfig(effective);
            tenantRepo.save(tenant);
            branding = effective;
        }

        try {
            // If the tenant has rich-login branding configured, fold the
            // layout variant + slot HTML on top of the uploaded zip so we
            // write ONE ConfigMap with both customizations in place.
            Map<String, byte[]> merged = (branding == null || branding.isEmpty())
                ? vr.extractedFiles()
                : brandingMerger.merge(vr.extractedFiles(), branding);
            storage.saveTheme(slug, merged);
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

    /**
     * Scans the uploaded zip for {@code mcpLayoutVariant=&lt;variant&gt;} in
     * {@code login/messages/messages_en.properties}. If found AND it differs
     * from the tenant's stored layout variant, returns an updated
     * {@link BrandingConfig} (preserving the existing slots map). Otherwise
     * returns the existing config unchanged.
     */
    static BrandingConfig reconcileLayoutFromZip(Map<String, byte[]> files, BrandingConfig existing) {
        if (files == null) return existing;
        byte[] msgs = files.get("login/messages/messages_en.properties");
        if (msgs == null) return existing;
        String declared = extractLayoutVariant(new String(msgs, StandardCharsets.UTF_8));
        if (declared == null) return existing;
        if (!BrandingConfig.ALLOWED_LAYOUT_VARIANTS.contains(declared)) return existing;

        String currentVariant = existing == null
            ? BrandingConfig.DEFAULT_LAYOUT_VARIANT
            : existing.layoutVariant();
        if (declared.equals(currentVariant)) return existing;

        // Preserve the existing slots map so the rest of the merge pipeline
        // (and the GET /branding response) still reflects whatever was there.
        Map<String, String> slots = existing == null || existing.slots() == null
            ? Map.of()
            : existing.slots();
        return new BrandingConfig(declared, slots);
    }

    private static final Pattern LAYOUT_VARIANT_LINE =
        Pattern.compile("(?m)^\\s*mcpLayoutVariant\\s*=\\s*(\\S+)\\s*$");

    private static String extractLayoutVariant(String propertiesText) {
        if (propertiesText == null || propertiesText.isEmpty()) return null;
        Matcher m = LAYOUT_VARIANT_LINE.matcher(propertiesText);
        // Take the LAST occurrence (rightmost wins, matching Properties semantics).
        String last = null;
        while (m.find()) {
            last = m.group(1);
        }
        return last;
    }

    public byte[] suggestedStarterFilename(String slug) {
        // helper exposed only because controllers prefer pure-data helpers
        return ("t-" + slug + "-starter.zip").getBytes(StandardCharsets.UTF_8);
    }
}
