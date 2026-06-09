package io.mcpmesh.auth.manager.email.templates;

import io.mcpmesh.auth.manager.theme.ThemeValidationException;
import io.mcpmesh.auth.manager.theme.ValidationResult;
import io.mcpmesh.auth.manager.theme.branding.BrandingHtmlSanitizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Parses + prescans a tenant email-template zip and generates the generic
 * starter zip.
 *
 * <p>Expected zip layout:
 * <pre>
 *   template.html   (required, Mustache body)
 *   subject.txt     (optional, Mustache subject)
 *   assets/&lt;files&gt; (optional inline images)
 * </pre>
 *
 * <p>Prescan reuses the branding sanitizer for the HTML body and the same
 * structural guards as the theme validator (size caps, path traversal,
 * extension allowlist). Validation failures are surfaced via
 * {@link ThemeValidationException} so they ride the existing 400 response
 * shape.
 */
@Component
public class EmailTemplateZip {

    private static final Logger log = LoggerFactory.getLogger(EmailTemplateZip.class);

    static final long MAX_ZIP_BYTES = 5L * 1024L * 1024L;
    static final long MAX_UNCOMPRESSED_BYTES = 5L * 1024L * 1024L;
    static final long MAX_PER_FILE_BYTES = 2L * 1024L * 1024L;
    static final int MAX_ENTRIES = 100;

    static final String TEMPLATE_HTML = "template.html";
    static final String SUBJECT_TXT = "subject.txt";
    static final String ASSETS_PREFIX = "assets/";

    /** Asset extensions permitted inside {@code assets/}. */
    static final Set<String> ALLOWED_ASSET_EXTENSIONS = Set.of(
        "png", "jpg", "jpeg", "gif", "svg"
    );

    private static final Map<String, String> CONTENT_TYPES = Map.of(
        "png", "image/png",
        "jpg", "image/jpeg",
        "jpeg", "image/jpeg",
        "gif", "image/gif",
        "svg", "image/svg+xml"
    );

    /** Matches {@code {{asset:NAME}}} (NAME without extension). */
    private static final java.util.regex.Pattern ASSET_REF =
        java.util.regex.Pattern.compile("\\{\\{\\s*asset:([a-zA-Z0-9_-]+)\\s*\\}\\}");

    /** Matches any remaining Mustache tag ({@code {{...}}} / {@code {{#x}}} / {@code {{/x}}}). */
    private static final java.util.regex.Pattern MUSTACHE_TAG =
        java.util.regex.Pattern.compile("\\{\\{[^}]*\\}\\}");

    private final BrandingHtmlSanitizer sanitizer;

    public EmailTemplateZip(BrandingHtmlSanitizer sanitizer) {
        this.sanitizer = sanitizer;
    }

    /**
     * Replaces Mustache tags with opaque placeholder tokens before HTML
     * sanitization (which otherwise neutralises {@code "{{"}), then restores the
     * original tags verbatim afterward.
     */
    static final class MustacheShield {
        private static final String TOKEN_PREFIX = "MUSTACHEx";
        private static final String TOKEN_SUFFIX = "xENDMUSTACHE";
        private final String shielded;
        private final List<String> tags;

        private MustacheShield(String shielded, List<String> tags) {
            this.shielded = shielded;
            this.tags = tags;
        }

        static MustacheShield protect(String html) {
            List<String> tags = new ArrayList<>();
            java.util.regex.Matcher m = MUSTACHE_TAG.matcher(html);
            StringBuilder sb = new StringBuilder();
            while (m.find()) {
                int idx = tags.size();
                tags.add(m.group());
                m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(
                    TOKEN_PREFIX + idx + TOKEN_SUFFIX));
            }
            m.appendTail(sb);
            return new MustacheShield(sb.toString(), tags);
        }

        String shielded() { return shielded; }

        String restore(String sanitized) {
            String out = sanitized;
            for (int i = 0; i < tags.size(); i++) {
                out = out.replace(TOKEN_PREFIX + i + TOKEN_SUFFIX, tags.get(i));
            }
            return out;
        }
    }

    /** Outcome of a successful parse + prescan. */
    public record Parsed(String html, String subject, List<TemplateAsset> assets) {}

    /**
     * Parses + prescans the zip. On any validation problem throws
     * {@link ThemeValidationException} carrying every collected error. On
     * success returns the sanitized HTML, optional subject, and asset list.
     */
    public Parsed parse(byte[] zipBytes) {
        List<ValidationResult.Error> errors = new ArrayList<>();

        if (zipBytes == null || zipBytes.length == 0) {
            throw fail(errors, "empty", "", "Uploaded file is empty");
        }
        if (zipBytes.length > MAX_ZIP_BYTES) {
            throw fail(errors, "zip_too_large", "",
                "Zip is " + zipBytes.length + " bytes; max is " + MAX_ZIP_BYTES);
        }

        Map<String, byte[]> files = new LinkedHashMap<>();
        if (!extract(zipBytes, files, errors)) {
            throw new ThemeValidationException(errors);
        }

        byte[] htmlBytes = files.get(TEMPLATE_HTML);
        if (htmlBytes == null) {
            errors.add(err("missing_template_html", TEMPLATE_HTML,
                "Zip must contain a top-level template.html"));
            throw new ThemeValidationException(errors);
        }

        // Sanitize the HTML body: strips <script>, on* handlers, JS-protocol
        // URLs. The OWASP sanitizer neutralises "{{" (template-injection
        // defense) and won't keep a Mustache tag inside an href/src, so we
        // first rewrite {{asset:NAME}} -> cid:NAME (a real, allowlisted URL
        // form) and protect the remaining {{ }} tags behind placeholder tokens
        // across the sanitize pass, restoring them afterwards.
        String rawHtml = new String(htmlBytes, StandardCharsets.UTF_8);
        String lower = rawHtml.toLowerCase(Locale.ROOT);
        if (lower.contains("<script") || lower.matches("(?s).*\\son[a-z]+\\s*=.*")) {
            log.warn("email-template: stripping script/handler content from template.html");
        }
        String withCids = ASSET_REF.matcher(rawHtml).replaceAll(m -> "cid:" + m.group(1));
        MustacheShield shield = MustacheShield.protect(withCids);
        String safeHtml = shield.restore(sanitizer.sanitize(shield.shielded()));
        if (safeHtml.isBlank()) {
            errors.add(err("empty_template_html", TEMPLATE_HTML,
                "template.html is empty after sanitization"));
        }

        String subject = null;
        byte[] subjectBytes = files.get(SUBJECT_TXT);
        if (subjectBytes != null) {
            String raw = new String(subjectBytes, StandardCharsets.UTF_8).strip();
            String s = raw.toLowerCase(Locale.ROOT);
            if (s.contains("<script") || s.contains("javascript:")) {
                errors.add(err("subject_forbidden_token", SUBJECT_TXT,
                    "subject.txt may not contain script / javascript: tokens"));
            }
            subject = raw.isEmpty() ? null : raw;
        }

        List<TemplateAsset> assets = new ArrayList<>();
        for (Map.Entry<String, byte[]> e : files.entrySet()) {
            String path = e.getKey();
            if (!path.startsWith(ASSETS_PREFIX)) {
                // README.md is part of the starter; ignore it (not stored, not
                // an error) so a round-trip download→re-upload just works.
                if (!path.equals(TEMPLATE_HTML) && !path.equals(SUBJECT_TXT)
                    && !path.equalsIgnoreCase("README.md")) {
                    errors.add(err("forbidden_path", path,
                        "Only template.html, subject.txt and assets/* are permitted"));
                }
                continue;
            }
            String name = path.substring(ASSETS_PREFIX.length());
            if (name.isEmpty() || name.contains("/")) {
                errors.add(err("nested_asset", path,
                    "Assets must be flat files under assets/ (no subdirectories)"));
                continue;
            }
            String ext = extensionOf(name);
            if (!ALLOWED_ASSET_EXTENSIONS.contains(ext)) {
                errors.add(err("forbidden_asset_extension", path,
                    "Asset extension not allowed: ." + ext));
                continue;
            }
            byte[] bytes = e.getValue();
            if ("svg".equals(ext)) {
                String svg = new String(bytes, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
                if (svg.contains("<script") || svg.contains("javascript:")
                    || svg.matches("(?s).*\\son[a-z]+\\s*=.*")
                    || svg.contains("href=\"http") || svg.contains("href='http")) {
                    errors.add(err("svg_unsafe", path,
                        "SVG asset contains script, event handlers, or remote refs"));
                    continue;
                }
            } else if (!magicOk(ext, bytes)) {
                errors.add(err("magic_byte_mismatch", path,
                    "Asset contents do not match its declared image type"));
                continue;
            }
            assets.add(new TemplateAsset(name, CONTENT_TYPES.get(ext), bytes));
        }

        if (!errors.isEmpty()) {
            throw new ThemeValidationException(errors);
        }
        return new Parsed(safeHtml, subject, assets);
    }

    // -- extraction -----------------------------------------------------------

    private boolean extract(byte[] zipBytes, Map<String, byte[]> files,
                            List<ValidationResult.Error> errors) {
        int count = 0;
        long total = 0;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (++count > MAX_ENTRIES) {
                    errors.add(err("too_many_entries", "",
                        "Zip has more than " + MAX_ENTRIES + " entries"));
                    return false;
                }
                String name = entry.getName();
                if (entry.isDirectory() || name.endsWith("/")) continue;
                if (name.startsWith("/") || name.contains("..")
                    || name.contains("\\") || name.contains("\0") || name.indexOf(':') >= 0) {
                    errors.add(err("path_traversal", name, "Entry path is not permitted: " + name));
                    return false;
                }
                byte[] content = readEntry(zis, name, errors);
                if (content == null) return false;
                total += content.length;
                if (total > MAX_UNCOMPRESSED_BYTES) {
                    errors.add(err("uncompressed_too_large", "",
                        "Total uncompressed size exceeds " + MAX_UNCOMPRESSED_BYTES));
                    return false;
                }
                files.put(name.replace('\\', '/'), content);
            }
        } catch (Exception e) {
            log.warn("email-template zip extraction failed", e);
            errors.add(err("zip_unreadable", "",
                "Zip stream is corrupt or unreadable: " + e.getMessage()));
            return false;
        }
        return true;
    }

    private byte[] readEntry(ZipInputStream zis, String name, List<ValidationResult.Error> errors) {
        try {
            byte[] buf = new byte[8192];
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int n;
            long total = 0;
            while ((n = zis.read(buf)) > 0) {
                total += n;
                if (total > MAX_PER_FILE_BYTES) {
                    errors.add(err("file_too_large", name, "File exceeds per-file size cap: " + name));
                    return null;
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } catch (Exception e) {
            errors.add(err("entry_unreadable", name, "Could not read zip entry: " + e.getMessage()));
            return null;
        }
    }

    // -- magic bytes ----------------------------------------------------------

    private static boolean magicOk(String ext, byte[] c) {
        return switch (ext) {
            case "png" -> startsWith(c, new byte[]{(byte) 0x89, 0x50, 0x4E, 0x47});
            case "jpg", "jpeg" -> startsWith(c, new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF});
            case "gif" -> startsWith(c, new byte[]{'G', 'I', 'F', '8'});
            default -> true;
        };
    }

    private static boolean startsWith(byte[] content, byte[] prefix) {
        if (content == null || content.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) {
            if (content[i] != prefix[i]) return false;
        }
        return true;
    }

    static String extensionOf(String name) {
        int dot = name.lastIndexOf('.');
        if (dot < 0) return "";
        return name.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    private static ValidationResult.Error err(String code, String path, String message) {
        return new ValidationResult.Error(code, path, message);
    }

    private static ThemeValidationException fail(List<ValidationResult.Error> errors,
                                                 String code, String path, String message) {
        errors.add(err(code, path, message));
        return new ThemeValidationException(errors);
    }

    // -- starter zip ----------------------------------------------------------

    /** Builds the generic starter zip (template.html, subject.txt, assets/, README.md). */
    public byte[] starterZip() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(out)) {
            put(zos, TEMPLATE_HTML, STARTER_HTML);
            put(zos, SUBJECT_TXT, STARTER_SUBJECT);
            put(zos, "README.md", STARTER_README);
            // Empty assets/ directory entry so the operator sees where to drop
            // files. Directory entries are skipped by the parser on re-upload.
            zos.putNextEntry(new ZipEntry(ASSETS_PREFIX));
            zos.closeEntry();
        } catch (IOException e) {
            throw new RuntimeException("Failed to assemble email-template starter zip", e);
        }
        return out.toByteArray();
    }

    private static void put(ZipOutputStream zos, String name, String body) throws IOException {
        zos.putNextEntry(new ZipEntry(name));
        zos.write(body.getBytes(StandardCharsets.UTF_8));
        zos.closeEntry();
    }

    private static final String STARTER_SUBJECT =
        "{{tenantDisplayName}} — action required\n";

    private static final String STARTER_HTML = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>{{tenantDisplayName}}</title>
          <style>
            .email-card { max-width: 480px; background-color: #ffffff; border-radius: 12px; border: 1px solid #e6e8eb; }
            .email-h1 { margin: 0; font-size: 24px; font-weight: 700; color: #111827; }
            .email-body { margin: 0; font-size: 16px; line-height: 1.5; color: #374151; }
            .email-cta { display: inline-block; background-color: #4f46e5; color: #ffffff; text-decoration: none; font-size: 16px; font-weight: 600; padding: 14px 28px; border-radius: 8px; }
          </style>
        </head>
        <body style="margin:0; padding:0; background-color:#f4f5f7; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f5f7; padding:24px 0;">
            <tr>
              <td align="center">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="email-card">
                  <tr>
                    <td style="padding:40px 40px 16px 40px; text-align:center;">
                      <img src="{{asset:logo}}" alt="{{tenantDisplayName}}" width="48" height="48" style="display:inline-block;">
                      <h1 class="email-h1">{{tenantDisplayName}}</h1>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding:0 40px 24px 40px; text-align:center;">
                      <p class="email-body">Replace this with your message to {{recipientEmail}}.</p>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding:0 40px 40px 40px; text-align:center;">
                      <a href="{{ctaUrl}}" class="email-cta">Take action</a>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
        """;

    private static final String STARTER_README = """
        # Tenant email template

        This zip is the starting point for a per-tenant transactional email
        template. Edit the files, zip the *contents* (not the parent folder),
        and upload via the Email Templates tab.

        ## Files

        - `template.html` — the email body. Logic-less **Mustache** is supported.
        - `subject.txt`   — the email subject line. Also Mustache. Optional.
        - `assets/`       — drop inline images here (png, jpg, jpeg, gif, svg).

        ## Mustache variables

        These are filled in at send time:

        - `{{tenantDisplayName}}` — the tenant's display name
        - `{{recipientEmail}}`    — the recipient's email address
        - `{{ctaUrl}}`            — the primary call-to-action URL
        - `{{inviterName}}`       — (invitation only) optional inviting admin

        ## Referencing an asset

        Reference a file in `assets/` from the HTML with `{{asset:NAME}}` where
        NAME is the filename without extension. For `assets/logo.png` use
        `<img src="{{asset:logo}}">`. (`cid:logo` is also accepted.) On send,
        the asset is attached as an inline `multipart/related` part and the
        reference is rewritten to its Content-ID.

        ## Styling rules

        - Use inline `style="..."` attributes for the most reliable rendering.
        - A single `<style>` block is supported: it is automatically inlined
          onto matching elements before send.
        - No `<script>`, no `on*` event handlers, no remote `<style>`/`@import`.
          These are stripped or rejected on upload.
        """;
}
