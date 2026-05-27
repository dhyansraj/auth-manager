package io.mcpmesh.auth.manager.theme.branding;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Pure-function merge of a {@link BrandingConfig} into a tenant's theme file
 * map. Produces the file map that {@link io.mcpmesh.auth.manager.theme.ThemeStorage}
 * writes into the per-tenant ConfigMap.
 *
 * <p>Three injection points (all under {@code login/}):
 * <ol>
 *   <li>{@code theme.properties}: ensures {@code parent=mcpmesh.flexible} so
 *       KC's theme inheritance picks up the platform-managed grid + template.</li>
 *   <li>{@code messages/messages_en.properties}: appends
 *       {@code mcpLayoutVariant=<variant>} and one
 *       {@code mcpmeshSlot<Name>Html=<sanitized>} per non-empty slot.</li>
 * </ol>
 *
 * <p>If the input file map is empty (tenant hasn't uploaded a zip but HAS
 * configured branding), the merger produces a minimal valid theme with just
 * {@code login/theme.properties} + {@code login/messages/messages_en.properties}.
 */
@Component
public class BrandingMerger {

    private static final Logger log = LoggerFactory.getLogger(BrandingMerger.class);

    static final String LOGIN_THEME_PROPERTIES = "login/theme.properties";
    static final String LOGIN_MESSAGES = "login/messages/messages_en.properties";
    static final String FLEXIBLE_PARENT = "mcpmesh-flexible";

    private static final Map<String, String> SLOT_KEY_BY_NAME = Map.of(
        "marketingLeft",  "mcpmeshSlotMarketingLeftHtml",
        "marketingRight", "mcpmeshSlotMarketingRightHtml",
        "aboveForm",      "mcpmeshSlotAboveFormHtml",
        "belowForm",      "mcpmeshSlotBelowFormHtml",
        "footer",         "mcpmeshSlotFooterHtml"
    );

    private final BrandingHtmlSanitizer sanitizer;

    public BrandingMerger(BrandingHtmlSanitizer sanitizer) {
        this.sanitizer = sanitizer;
    }

    /**
     * Returns a new file map with branding-driven overlays applied.
     * The input map is not mutated. If {@code config} is null or empty
     * (no real customization), the input is returned as-is.
     */
    public Map<String, byte[]> merge(Map<String, byte[]> inputFiles, BrandingConfig config) {
        if (config == null || config.isEmpty()) {
            return inputFiles == null ? Map.of() : inputFiles;
        }
        Map<String, byte[]> out = new LinkedHashMap<>();
        if (inputFiles != null) out.putAll(inputFiles);

        // ----- 1) ensure login/theme.properties has parent=mcpmesh.flexible -----
        byte[] existingProps = out.get(LOGIN_THEME_PROPERTIES);
        String mergedProps = rewriteParent(
            existingProps == null ? "" : new String(existingProps, StandardCharsets.UTF_8));
        out.put(LOGIN_THEME_PROPERTIES, mergedProps.getBytes(StandardCharsets.UTF_8));

        // ----- 2) append slot keys + layout variant to messages_en.properties --
        byte[] existingMsgs = out.get(LOGIN_MESSAGES);
        String mergedMsgs = appendBrandingMessages(
            existingMsgs == null ? "" : new String(existingMsgs, StandardCharsets.UTF_8),
            config);
        out.put(LOGIN_MESSAGES, mergedMsgs.getBytes(StandardCharsets.UTF_8));

        log.debug("BrandingMerger: produced {} files (variant={}, slotsConfigured={})",
            out.size(), config.layoutVariant(),
            config.slots() == null ? 0 : config.slots().size());
        return out;
    }

    /**
     * Rewrites {@code parent=...} to {@code parent=mcpmesh.flexible}. Adds the
     * line if absent. Preserves all other lines (including comments, imports,
     * and styles=) so tenant CSS customization is not lost.
     */
    static String rewriteParent(String original) {
        StringBuilder out = new StringBuilder();
        boolean parentWritten = false;
        for (String line : original.split("\\r?\\n", -1)) {
            String trimmed = line.trim();
            if (trimmed.startsWith("parent=") || trimmed.startsWith("parent ")) {
                if (!parentWritten) {
                    out.append("parent=").append(FLEXIBLE_PARENT).append('\n');
                    parentWritten = true;
                }
                // Drop the original parent= line — we replaced it above.
            } else {
                out.append(line).append('\n');
            }
        }
        if (!parentWritten) {
            // Theme had no parent= line at all (or was empty). Prepend ours.
            return "parent=" + FLEXIBLE_PARENT + "\n" + out;
        }
        return out.toString();
    }

    /**
     * Appends a {@code # --- mcpmesh.flexible (managed) ---} block to the end
     * of the existing properties content. Idempotent: a second merge will
     * find the previous block, strip it, and re-emit a fresh one.
     */
    String appendBrandingMessages(String original, BrandingConfig config) {
        String stripped = stripManagedBlock(original);
        StringBuilder out = new StringBuilder(stripped);
        if (!stripped.isEmpty() && !stripped.endsWith("\n")) {
            out.append('\n');
        }
        out.append("\n# --- mcpmesh.flexible (managed; do not edit; regenerated on save) ---\n");
        out.append("mcpLayoutVariant=").append(config.layoutVariant()).append('\n');
        if (config.slots() != null) {
            for (Map.Entry<String, String> e : config.slots().entrySet()) {
                String slotName = e.getKey();
                String key = SLOT_KEY_BY_NAME.get(slotName);
                if (key == null) continue;  // unknown slot — drop silently
                String raw = e.getValue();
                if (raw == null || raw.isBlank()) continue;
                String sanitized = sanitizer.sanitize(raw);
                if (sanitized.isEmpty()) continue;
                out.append(key).append('=').append(escapePropertyValue(sanitized)).append('\n');
            }
        }
        out.append("# --- /mcpmesh.flexible ---\n");
        return out.toString();
    }

    /**
     * Removes a previously-written managed block (between the open/close
     * marker comments) so that a re-merge produces fresh content rather
     * than appending duplicates.
     */
    static String stripManagedBlock(String text) {
        int open = text.indexOf("# --- mcpmesh.flexible (managed");
        if (open < 0) return text;
        int close = text.indexOf("# --- /mcpmesh.flexible ---", open);
        if (close < 0) return text;  // malformed; leave alone
        int endOfClose = text.indexOf('\n', close);
        if (endOfClose < 0) endOfClose = text.length();
        else endOfClose += 1;
        String before = text.substring(0, open);
        String after = text.substring(endOfClose);
        // Trim trailing whitespace newlines on `before` so we don't accumulate blank lines.
        while (before.endsWith("\n\n")) before = before.substring(0, before.length() - 1);
        return before + after;
    }

    /**
     * Java .properties escaping: backslashes, newlines, and carriage returns
     * must be escaped. Values may contain any of these after HTML sanitization
     * (e.g. {@code <a href="..."}) so we apply the minimum-viable escape set.
     *
     * <p>Keycloak parses these files via {@link java.util.Properties}, which
     * implements the standard JDK rules. We do NOT escape '=' or ':' in
     * values (only in keys would they need escaping).
     */
    static String escapePropertyValue(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> out.append(c);
            }
        }
        return out.toString();
    }
}
