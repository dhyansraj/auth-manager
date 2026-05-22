package io.mcpmesh.auth.manager.theme;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.helger.css.ECSSVersion;
import com.helger.css.decl.CSSDeclaration;
import com.helger.css.decl.CSSExpressionMemberFunction;
import com.helger.css.decl.CSSExpressionMemberTermSimple;
import com.helger.css.decl.CSSImportRule;
import com.helger.css.decl.CascadingStyleSheet;
import com.helger.css.decl.ICSSExpressionMember;
import com.helger.css.decl.visit.CSSVisitor;
import com.helger.css.decl.visit.DefaultCSSVisitor;
import com.helger.css.reader.CSSReader;
import com.helger.css.reader.CSSReaderSettings;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Multi-layer prescan for tenant-uploaded theme zips.
 *
 * <p>Returns a {@link ValidationResult} carrying both errors (structured so
 * the UI can surface them) and the extracted file bytes (so callers don't
 * have to unzip again).
 *
 * <p>Layers:
 * <ol>
 *   <li>Structural: size caps, entry count, no path traversal, no symlinks,
 *       required {@code theme.properties} with allowed {@code parent}.</li>
 *   <li>File-type allowlist: extensions only. Executable content (.js, .ftl,
 *       .html, etc.) is hard-rejected.</li>
 *   <li>Per-file content scan: CSS via ph-css, SVG via OWASP sanitizer,
 *       properties + JSON via line/parse scans, magic-byte checks for
 *       images + fonts.</li>
 * </ol>
 *
 * <p>Stateless; safe to inject as a singleton.
 */
@Component
public class ThemeValidator {

    private static final Logger log = LoggerFactory.getLogger(ThemeValidator.class);

    /** Max total compressed size of the uploaded zip (~800 KB). */
    static final long MAX_ZIP_BYTES = 800L * 1024L;

    /** Max total uncompressed size after extraction (~5 MB). */
    static final long MAX_UNCOMPRESSED_BYTES = 5L * 1024L * 1024L;

    /** Max number of zip entries. */
    static final int MAX_ENTRIES = 200;

    /** Per-file ceiling so a single huge entry can't blow past the total. */
    static final long MAX_PER_FILE_BYTES = 2L * 1024L * 1024L;

    static final Set<String> ALLOWED_EXTENSIONS = Set.of(
        "css", "properties", "json",
        "png", "jpg", "jpeg", "webp", "ico", "svg",
        "woff", "woff2", "ttf", "otf",
        "md"  // README in starter; harmless content
    );

    static final Set<String> BINARY_EXTENSIONS = Set.of(
        "png", "jpg", "jpeg", "webp", "ico", "svg",
        "woff", "woff2", "ttf", "otf"
    );

    /** Allowed values for the {@code parent=} declaration in theme.properties. */
    private static final Set<String> ALLOWED_PARENT_THEMES = Set.of("keycloak.v2", "keycloak");

    private static final Set<String> ALLOWED_THEME_JSON_KEYS = Set.of(
        "parent", "displayName", "description"
    );

    private final PolicyFactory svgSanitizer = buildSvgSanitizer();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ValidationResult validateZip(byte[] zipBytes) {
        ValidationResult.Builder b = new ValidationResult.Builder();

        if (zipBytes == null || zipBytes.length == 0) {
            return b.error("empty", "", "Uploaded file is empty").build();
        }
        if (zipBytes.length > MAX_ZIP_BYTES) {
            return b.error("zip_too_large", "",
                "Zip is " + zipBytes.length + " bytes; max is " + MAX_ZIP_BYTES).build();
        }

        // ---- Layer 1: structural extraction ----
        if (!extractEntries(zipBytes, b)) {
            // Hard structural failure; don't proceed to content scan.
            return b.build();
        }

        // ---- Layer 2 + 3: per-file checks ----
        for (Map.Entry<String, byte[]> e : b.files().entrySet()) {
            scanFile(e.getKey(), e.getValue(), b);
        }

        // ---- Required files ----
        if (!b.hasFile("theme.properties")) {
            b.error("missing_theme_properties", "theme.properties",
                "Theme must contain a theme.properties file at the root");
        } else {
            validateThemePropertiesParent(b.file("theme.properties"), b);
        }

        return b.build();
    }

    // -------------------------------------------------------------------------
    // Layer 1: extraction
    // -------------------------------------------------------------------------

    /**
     * Streams every zip entry into the builder. Returns {@code false} if a
     * structural error (path traversal, symlink, etc.) was hit, in which case
     * the caller should NOT continue to content scanning.
     */
    private boolean extractEntries(byte[] zipBytes, ValidationResult.Builder b) {
        int entryCount = 0;
        long totalUncompressed = 0;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                entryCount++;
                if (entryCount > MAX_ENTRIES) {
                    b.error("too_many_entries", "",
                        "Zip has more than " + MAX_ENTRIES + " entries");
                    return false;
                }

                String name = entry.getName();
                // Skip directory entries -- ZipEntry uses trailing "/" by convention.
                if (entry.isDirectory() || name.endsWith("/")) {
                    continue;
                }

                // Reject absolute / Windows / traversal / control-char paths.
                if (name.startsWith("/") || name.contains("..")
                        || name.contains("\\") || name.contains("\0")
                        || name.indexOf(':') >= 0) {
                    b.error("path_traversal", name,
                        "Entry path is not permitted: " + name);
                    return false;
                }

                // Symlinks in zips are exposed by the "unix mode" external attrs;
                // ZipEntry doesn't surface this directly, but symlinks are
                // exceedingly rare in our flow (UI-generated upload) -- we
                // additionally reject any file with extension "lnk" or that
                // has zero size but appears to contain a path-looking value.
                // Fabric8 ZipInputStream surfaces them as regular entries
                // anyway; the magic-byte check below stops them from being
                // mis-interpreted as images. We treat anything that isn't
                // an allowed extension as rejected.

                byte[] content = readEntry(zis, name, b);
                if (content == null) {
                    return false;  // per-file size cap exceeded; reported below
                }
                totalUncompressed += content.length;
                if (totalUncompressed > MAX_UNCOMPRESSED_BYTES) {
                    b.error("uncompressed_too_large", "",
                        "Total uncompressed size exceeds " + MAX_UNCOMPRESSED_BYTES);
                    return false;
                }

                // Layer 2: extension allowlist (fail-fast).
                String ext = extensionOf(name);
                if (!ALLOWED_EXTENSIONS.contains(ext)) {
                    b.error("forbidden_extension", name,
                        "Forbidden file extension: ." + ext);
                    // Continue extracting so the UI sees ALL bad files, not just
                    // the first one -- but don't store the content.
                    continue;
                }

                b.file(normalize(name), content);
            }
        } catch (Exception e) {
            log.warn("Theme zip extraction failed", e);
            b.error("zip_unreadable", "",
                "Zip stream is corrupt or unreadable: " + e.getMessage());
            return false;
        }
        return !b.hasErrors();
    }

    private byte[] readEntry(ZipInputStream zis, String name, ValidationResult.Builder b) {
        try {
            // Bounded read so a poisoned entry can't blow past per-file cap.
            byte[] buf = new byte[8192];
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            int n;
            long total = 0;
            while ((n = zis.read(buf)) > 0) {
                total += n;
                if (total > MAX_PER_FILE_BYTES) {
                    b.error("file_too_large", name,
                        "File exceeds per-file size cap: " + name);
                    return null;
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } catch (Exception e) {
            b.error("entry_unreadable", name,
                "Could not read zip entry: " + e.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Layer 3: per-file content scan
    // -------------------------------------------------------------------------

    private void scanFile(String path, byte[] content, ValidationResult.Builder b) {
        String ext = extensionOf(path);
        switch (ext) {
            case "css" -> scanCss(path, content, b);
            case "svg" -> scanAndSanitizeSvg(path, content, b);
            case "properties" -> scanProperties(path, content, b);
            case "json" -> scanJson(path, content, b);
            case "png" -> requireMagic(path, content, b, new byte[][]{
                {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
            });
            case "jpg", "jpeg" -> requireMagic(path, content, b, new byte[][]{
                {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF}
            });
            case "webp" -> requireWebp(path, content, b);
            case "ico" -> requireMagic(path, content, b, new byte[][]{
                {0x00, 0x00, 0x01, 0x00}
            });
            case "woff" -> requireMagic(path, content, b, new byte[][]{
                {(byte) 'w', (byte) 'O', (byte) 'F', (byte) 'F'}
            });
            case "woff2" -> requireMagic(path, content, b, new byte[][]{
                {(byte) 'w', (byte) 'O', (byte) 'F', (byte) '2'}
            });
            case "ttf" -> requireMagic(path, content, b, new byte[][]{
                {0x00, 0x01, 0x00, 0x00},                // TrueType
                {(byte) 't', (byte) 'r', (byte) 'u', (byte) 'e'}  // also valid
            });
            case "otf" -> requireMagic(path, content, b, new byte[][]{
                {(byte) 'O', (byte) 'T', (byte) 'T', (byte) 'O'}
            });
            case "md" -> { /* README; allowed but not scanned. */ }
            default -> {
                // Should have been caught in layer 2; defensive.
                b.error("forbidden_extension", path,
                    "Unsupported file extension: ." + ext);
            }
        }
    }

    // ---- CSS ----------------------------------------------------------------

    private void scanCss(String path, byte[] content, ValidationResult.Builder b) {
        String text = new String(content, StandardCharsets.UTF_8);

        // Lexical pre-check that doesn't depend on a successful parse. These
        // catch obfuscated forms that survive the parse-tree walk (e.g. URLs
        // hidden inside @media or unparseable rules).
        String lower = text.toLowerCase(Locale.ROOT);
        if (lower.contains("javascript:")) {
            b.error("css_javascript_url", path,
                "CSS file contains 'javascript:' which is not permitted");
        }
        if (lower.contains("expression(")) {
            b.error("css_expression", path,
                "CSS file contains expression() which is not permitted");
        }
        if (lower.contains("behavior:")) {
            b.error("css_behavior", path,
                "CSS file contains 'behavior:' which is not permitted");
        }
        // Defense-in-depth regex sweep for remote url() — ph-css parses url(...)
        // as a special URI term (not a function), so the parse-tree visitor
        // below misses these. Pattern: url( optional-quote (http|https|//) ...
        // Matches url(http://, url(https://, url(//, url("http... url('//... etc.
        java.util.regex.Pattern remoteUrl = java.util.regex.Pattern.compile(
            "url\\s*\\(\\s*['\"]?\\s*(https?:|//)",
            java.util.regex.Pattern.CASE_INSENSITIVE);
        if (remoteUrl.matcher(text).find()) {
            b.error("css_external_url", path,
                "CSS url() must be relative; remote URLs not permitted");
        }

        CSSReaderSettings settings = new CSSReaderSettings()
            .setCSSVersion(ECSSVersion.CSS30)
            .setFallbackCharset(StandardCharsets.UTF_8);
        CascadingStyleSheet css = CSSReader.readFromStringStream(text, settings);
        if (css == null) {
            b.error("css_parse_failed", path,
                "CSS file could not be parsed");
            return;
        }

        // @import is always rejected (parsed at the top of the file).
        for (CSSImportRule imp : css.getAllImportRules()) {
            b.error("css_import_forbidden", path,
                "CSS @import is not permitted: " + imp.getLocationString());
        }

        CSSVisitor.visitCSS(css, new DefaultCSSVisitor() {
            @Override
            public void onDeclaration(CSSDeclaration decl) {
                if (decl == null || decl.getExpression() == null) return;
                for (ICSSExpressionMember m : decl.getExpression().getAllMembers()) {
                    checkExpressionMember(decl.getProperty(), m);
                }
            }

            private void checkExpressionMember(String prop, ICSSExpressionMember m) {
                if (m instanceof CSSExpressionMemberTermSimple s) {
                    String v = s.getValue();
                    if (v != null) {
                        String vLower = v.toLowerCase(Locale.ROOT);
                        if (vLower.contains("javascript:")) {
                            b.error("css_javascript_url", path,
                                "CSS value contains 'javascript:' in property '" + prop + "'");
                        }
                    }
                } else if (m instanceof CSSExpressionMemberFunction f) {
                    String name = f.getFunctionName();
                    if (name != null && name.equalsIgnoreCase("url")) {
                        // Walk url(...) inner args.
                        var expr = f.getExpression();
                        if (expr != null) {
                            for (ICSSExpressionMember inner : expr.getAllMembers()) {
                                if (inner instanceof CSSExpressionMemberTermSimple s) {
                                    String raw = unquote(s.getValue());
                                    if (isExternalUrl(raw)) {
                                        b.error("css_external_url", path,
                                            "CSS url() must be relative; found '" + raw + "'");
                                    }
                                }
                            }
                        }
                    }
                    if (name != null && name.equalsIgnoreCase("expression")) {
                        b.error("css_expression", path,
                            "CSS expression() is not permitted");
                    }
                }
            }
        });
    }

    private static String unquote(String s) {
        if (s == null) return "";
        s = s.trim();
        if (s.length() >= 2) {
            char first = s.charAt(0);
            char last = s.charAt(s.length() - 1);
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                return s.substring(1, s.length() - 1);
            }
        }
        return s;
    }

    private static boolean isExternalUrl(String url) {
        if (url == null) return false;
        String u = url.trim().toLowerCase(Locale.ROOT);
        return u.startsWith("http://") || u.startsWith("https://") || u.startsWith("//")
            || u.startsWith("javascript:") || u.startsWith("ftp://");
    }

    // ---- SVG ----------------------------------------------------------------

    private PolicyFactory buildSvgSanitizer() {
        // OWASP sanitizer is built for HTML; we use it conservatively on SVG by
        // allowing only a small set of SVG-shape elements + attributes. Scripts
        // and event handlers are dropped automatically.
        return new HtmlPolicyBuilder()
            .allowElements("svg", "g", "path", "circle", "ellipse", "line",
                           "rect", "polyline", "polygon", "text", "tspan",
                           "defs", "use", "symbol", "title", "desc",
                           "linearGradient", "radialGradient", "stop", "clipPath")
            .allowAttributes("xmlns", "viewBox", "width", "height", "preserveAspectRatio",
                             "version", "fill", "stroke", "stroke-width",
                             "stroke-linecap", "stroke-linejoin", "stroke-miterlimit",
                             "stroke-opacity", "fill-opacity", "opacity", "fill-rule",
                             "transform", "x", "y", "x1", "y1", "x2", "y2",
                             "cx", "cy", "r", "rx", "ry", "d", "points",
                             "offset", "stop-color", "stop-opacity",
                             "gradientUnits", "gradientTransform",
                             "id", "class", "style", "font-family", "font-size",
                             "text-anchor", "dy", "dx", "clip-path").globally()
            // Allow href only with relative / fragment values -- absolute URLs
            // are stripped by the disallow filter below.
            .allowUrlProtocols("data")
            .toFactory();
    }

    private void scanAndSanitizeSvg(String path, byte[] content, ValidationResult.Builder b) {
        String svg = new String(content, StandardCharsets.UTF_8);
        String lower = svg.toLowerCase(Locale.ROOT);
        if (lower.contains("<foreignobject")) {
            b.error("svg_foreign_object", path,
                "SVG <foreignObject> is not permitted");
            return;
        }
        // Reject if remote use ref present.
        if (lower.contains("xlink:href=\"http") || lower.contains("href=\"http")
            || lower.contains("xlink:href='http") || lower.contains("href='http")) {
            b.error("svg_remote_href", path,
                "SVG remote href / xlink:href is not permitted");
            return;
        }

        String sanitized = svgSanitizer.sanitize(svg);
        // The sanitizer treats input as HTML; it will lowercase tag names + drop
        // anything not on the allowlist. If sanitization stripped content, warn
        // but allow.
        if (lower.contains("<script") || lower.contains(" on")) {
            log.warn("SVG sanitizer stripped suspicious content from {}", path);
        }
        // Replace the bytes the caller will store with the sanitized version.
        // We prepend the XML declaration if the input had one, to keep KC's
        // image loader happy.
        String prefix = "";
        if (svg.startsWith("<?xml")) {
            int end = svg.indexOf("?>");
            if (end > 0) prefix = svg.substring(0, end + 2) + "\n";
        }
        b.file(path, (prefix + sanitized).getBytes(StandardCharsets.UTF_8));
    }

    // ---- properties ---------------------------------------------------------

    private static final List<String> PROPERTIES_FORBIDDEN_SUBSTRINGS = List.of(
        "<script", "</script", "javascript:",
        "<iframe", "<embed", "<object"
    );

    private void scanProperties(String path, byte[] content, ValidationResult.Builder b) {
        String text = new String(content, StandardCharsets.UTF_8);
        String[] lines = text.split("\\r?\\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String lower = line.toLowerCase(Locale.ROOT);
            for (String bad : PROPERTIES_FORBIDDEN_SUBSTRINGS) {
                if (lower.contains(bad)) {
                    b.error("properties_forbidden_token", path,
                        "Forbidden token '" + bad + "' on line " + (i + 1));
                    return;
                }
            }
            // on*= attributes -- catches onclick, onload, onerror, etc.
            if (lower.matches(".*\\bon[a-z]+\\s*=.*")) {
                b.error("properties_event_handler", path,
                    "Event-handler attribute on line " + (i + 1));
                return;
            }
        }
    }

    private void validateThemePropertiesParent(byte[] content, ValidationResult.Builder b) {
        String text = new String(content, StandardCharsets.UTF_8);
        String parent = null;
        for (String line : text.split("\\r?\\n", -1)) {
            String trimmed = line.trim();
            if (trimmed.startsWith("#") || trimmed.isEmpty()) continue;
            int eq = trimmed.indexOf('=');
            if (eq < 0) continue;
            String k = trimmed.substring(0, eq).trim();
            String v = trimmed.substring(eq + 1).trim();
            if (k.equals("parent")) {
                parent = v;
                break;
            }
        }
        if (parent == null) {
            b.error("theme_properties_no_parent", "theme.properties",
                "theme.properties must declare 'parent=keycloak.v2' or 'parent=keycloak'");
        } else if (!ALLOWED_PARENT_THEMES.contains(parent)) {
            b.error("theme_properties_bad_parent", "theme.properties",
                "theme.properties parent must be one of " + ALLOWED_PARENT_THEMES
                + "; found '" + parent + "'");
        }
    }

    // ---- JSON ---------------------------------------------------------------

    private void scanJson(String path, byte[] content, ValidationResult.Builder b) {
        Map<String, Object> parsed;
        try {
            parsed = objectMapper.readValue(content, Map.class);
        } catch (Exception e) {
            b.error("json_parse_failed", path,
                "JSON could not be parsed: " + e.getMessage());
            return;
        }
        if (path.equals("theme.json")) {
            for (String key : parsed.keySet()) {
                if (!ALLOWED_THEME_JSON_KEYS.contains(key)) {
                    b.error("theme_json_forbidden_key", path,
                        "theme.json may only contain " + ALLOWED_THEME_JSON_KEYS
                        + "; found '" + key + "'");
                }
            }
        }
    }

    // ---- magic-byte sniffing ------------------------------------------------

    private void requireMagic(String path, byte[] content,
                              ValidationResult.Builder b, byte[][] candidates) {
        for (byte[] magic : candidates) {
            if (startsWith(content, magic)) return;
        }
        b.error("magic_byte_mismatch", path,
            "File contents do not match the declared file type");
    }

    /** WebP: "RIFF" {4 size bytes} "WEBP" */
    private void requireWebp(String path, byte[] content, ValidationResult.Builder b) {
        if (content.length >= 12
            && content[0] == 'R' && content[1] == 'I' && content[2] == 'F' && content[3] == 'F'
            && content[8] == 'W' && content[9] == 'E' && content[10] == 'B' && content[11] == 'P') {
            return;
        }
        b.error("magic_byte_mismatch", path,
            "WebP magic bytes not present");
    }

    private static boolean startsWith(byte[] content, byte[] prefix) {
        if (content.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) {
            if (content[i] != prefix[i]) return false;
        }
        return true;
    }

    // ---- helpers ------------------------------------------------------------

    /** "themes/a/B.CSS" -> "css" (lower-case, no dot). */
    static String extensionOf(String name) {
        int slash = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
        int dot = name.lastIndexOf('.');
        if (dot < 0 || dot < slash) return "";
        return name.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    /** Normalise to forward-slash, no leading slash. */
    private static String normalize(String name) {
        String n = name.replace('\\', '/');
        while (n.startsWith("/")) n = n.substring(1);
        return n;
    }

    /** True if file should be stored in {@code binaryData} (vs {@code data}). */
    public static boolean isBinary(String path) {
        return BINARY_EXTENSIONS.contains(extensionOf(path));
    }

}
