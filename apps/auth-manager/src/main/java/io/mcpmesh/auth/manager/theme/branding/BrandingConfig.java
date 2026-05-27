package io.mcpmesh.auth.manager.theme.branding;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Per-tenant "rich login" configuration: layout variant + slot HTML map.
 *
 * <p>The layout variant selects one of the platform-managed {@code mcpmesh.flexible}
 * CSS grid templates (centered / split-left / split-right / bleed). The slots
 * map carries arbitrary HTML keyed by slot name; the
 * {@link io.mcpmesh.auth.manager.theme.ThemeApplier} merges these into the
 * tenant's compiled theme as messages_en.properties keys.
 *
 * <p>Persisted on the tenants table as a JSONB column. Stored as-typed by
 * operators; sanitized server-side by {@link BrandingHtmlSanitizer} only at
 * the point of being written into the tenant theme files (so the raw text
 * round-trips through the API for editing).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record BrandingConfig(
    String layoutVariant,
    Map<String, String> slots
) {

    public static final String DEFAULT_LAYOUT_VARIANT = "centered";

    public static final Set<String> ALLOWED_LAYOUT_VARIANTS = Set.of(
        "centered", "split-left", "split-right", "bleed"
    );

    /** Canonical slot names. Anything else in {@code slots} is ignored. */
    public static final Set<String> ALLOWED_SLOT_NAMES = Set.of(
        "marketingLeft", "marketingRight", "aboveForm", "belowForm", "footer"
    );

    @JsonCreator
    public BrandingConfig(
        @JsonProperty("layoutVariant") String layoutVariant,
        @JsonProperty("slots") Map<String, String> slots
    ) {
        this.layoutVariant = (layoutVariant == null || layoutVariant.isBlank())
            ? DEFAULT_LAYOUT_VARIANT
            : layoutVariant;
        // Defensive copy + preserve insertion order; strip nulls.
        Map<String, String> copy = new LinkedHashMap<>();
        if (slots != null) {
            for (Map.Entry<String, String> e : slots.entrySet()) {
                if (e.getKey() == null) continue;
                copy.put(e.getKey(), e.getValue() == null ? "" : e.getValue());
            }
        }
        this.slots = Map.copyOf(copy);
    }

    /** Empty config ("centered" + no slots) used when no row exists yet. */
    public static BrandingConfig empty() {
        return new BrandingConfig(DEFAULT_LAYOUT_VARIANT, Map.of());
    }

    /** True iff this config carries any real customization. */
    @JsonIgnore
    public boolean isEmpty() {
        if (slots != null) {
            for (String v : slots.values()) {
                if (v != null && !v.isBlank()) return false;
            }
        }
        return DEFAULT_LAYOUT_VARIANT.equals(layoutVariant);
    }
}
