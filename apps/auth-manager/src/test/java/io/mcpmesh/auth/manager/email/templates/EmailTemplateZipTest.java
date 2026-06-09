package io.mcpmesh.auth.manager.email.templates;

import io.mcpmesh.auth.manager.theme.ThemeValidationException;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Prescan tests for the email-template zip parser. */
class EmailTemplateZipTest {

    private final EmailTemplateZip zip = new EmailTemplateZip(new EmailHtmlSanitizer());

    private static byte[] makeZip(Map<String, byte[]> entries) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(out)) {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                zos.putNextEntry(new ZipEntry(e.getKey()));
                zos.write(e.getValue());
                zos.closeEntry();
            }
        }
        return out.toByteArray();
    }

    private static byte[] bytes(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    @Test
    void validZip_parsesHtmlSubjectAndAssets() throws Exception {
        byte[] png = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("template.html", bytes("<p>Hello {{tenantDisplayName}} <img src=\"{{asset:logo}}\"></p>"));
        entries.put("subject.txt", bytes("Hi {{tenantDisplayName}}"));
        entries.put("assets/logo.png", png);

        EmailTemplateZip.Parsed parsed = zip.parse(makeZip(entries));
        assertThat(parsed.html()).contains("{{tenantDisplayName}}");
        // {{asset:logo}} is rewritten to a cid: reference at upload time.
        assertThat(parsed.html()).contains("cid:logo");
        assertThat(parsed.html()).doesNotContain("asset:logo");
        assertThat(parsed.subject()).isEqualTo("Hi {{tenantDisplayName}}");
        assertThat(parsed.assets()).hasSize(1);
        assertThat(parsed.assets().get(0).name()).isEqualTo("logo.png");
        assertThat(parsed.assets().get(0).contentType()).isEqualTo("image/png");
    }

    @Test
    void missingTemplateHtml_isRejected() throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("subject.txt", bytes("Hi"));
        assertThatThrownBy(() -> zip.parse(makeZip(entries)))
            .isInstanceOf(ThemeValidationException.class);
    }

    @Test
    void forbiddenAssetExtension_isRejected() throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("template.html", bytes("<p>ok</p>"));
        entries.put("assets/evil.js", bytes("alert(1)"));
        assertThatThrownBy(() -> zip.parse(makeZip(entries)))
            .isInstanceOf(ThemeValidationException.class)
            .satisfies(ex -> assertThat(((ThemeValidationException) ex).errors())
                .anyMatch(e -> e.code().equals("forbidden_asset_extension")));
    }

    @Test
    void scriptInTemplateHtml_isStrippedBySanitizer() throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("template.html",
            bytes("<p>hi</p><script>steal()</script><a href=\"javascript:evil()\">x</a>"));
        EmailTemplateZip.Parsed parsed = zip.parse(makeZip(entries));
        assertThat(parsed.html().toLowerCase()).doesNotContain("<script");
        assertThat(parsed.html().toLowerCase()).doesNotContain("javascript:");
    }

    @Test
    void xssInSvgAsset_isRejected() throws Exception {
        String svg = "<svg xmlns=\"http://www.w3.org/2000/svg\">"
            + "<script>alert(1)</script></svg>";
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("template.html", bytes("<p>ok</p>"));
        entries.put("assets/bad.svg", bytes(svg));
        assertThatThrownBy(() -> zip.parse(makeZip(entries)))
            .isInstanceOf(ThemeValidationException.class)
            .satisfies(ex -> assertThat(((ThemeValidationException) ex).errors())
                .anyMatch(e -> e.code().equals("svg_unsafe")));
    }

    @Test
    void pathTraversal_isRejected() throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("../../etc/passwd", bytes("x"));
        assertThatThrownBy(() -> zip.parse(makeZip(entries)))
            .isInstanceOf(ThemeValidationException.class);
    }

    @Test
    void realEmailTemplate_keepsTablesButtonInlineCss_andMustache() throws Exception {
        String html = """
            <table cellpadding="0" cellspacing="0" align="center" bgcolor="#f4f5f7" width="600">
              <tr>
                <td valign="top" style="padding:24px; color:#111827;">
                  {{#inviterName}}<p>Invited by {{inviterName}}</p>{{/inviterName}}
                  <p>Sent to {{recipientEmail}}</p>
                  <table cellpadding="0" cellspacing="0">
                    <tr>
                      <td bgcolor="#4f46e5" align="center" style="border-radius:8px;">
                        <a href="{{ctaUrl}}" style="display:inline-block; padding:14px 28px; color:#ffffff; text-decoration:none;">Accept</a>
                      </td>
                    </tr>
                  </table>
                  <img src="{{asset:logo}}" alt="logo" width="48">
                </td>
              </tr>
            </table>
            """;
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("template.html", bytes(html));
        byte[] png = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
        entries.put("assets/logo.png", png);

        EmailTemplateZip.Parsed parsed = zip.parse(makeZip(entries));
        String out = parsed.html();

        // Table layout survives.
        assertThat(out).contains("<table");
        assertThat(out).contains("<td");
        // Presentational attributes survive.
        assertThat(out).contains("cellpadding=\"0\"");
        assertThat(out).contains("bgcolor=\"#4f46e5\"");
        assertThat(out).contains("align=\"center\"");
        assertThat(out).contains("valign=\"top\"");
        // Inline CSS survives verbatim.
        assertThat(out).contains("padding:14px 28px");
        assertThat(out).contains("border-radius:8px");
        // Table-button anchor with its Mustache href restored.
        assertThat(out).contains("href=\"{{ctaUrl}}\"");
        // Asset img rewritten to cid:.
        assertThat(out).contains("cid:logo");
        // Mustache section + var tags intact.
        assertThat(out).contains("{{#inviterName}}");
        assertThat(out).contains("{{/inviterName}}");
        assertThat(out).contains("{{recipientEmail}}");
    }

    @Test
    void starterZip_isParseableByOwnParser() {
        byte[] starter = zip.starterZip();
        EmailTemplateZip.Parsed parsed = zip.parse(starter);
        assertThat(parsed.html()).contains("{{tenantDisplayName}}");
        assertThat(parsed.subject()).contains("{{tenantDisplayName}}");
    }
}
