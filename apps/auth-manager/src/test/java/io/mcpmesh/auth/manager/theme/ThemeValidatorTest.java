package io.mcpmesh.auth.manager.theme;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

class ThemeValidatorTest {

    private final ThemeValidator validator = new ThemeValidator();

    // ---- happy path --------------------------------------------------------

    @Test
    void validZip_isAccepted() throws Exception {
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\nstyles=css/custom.css\n".getBytes(),
            "resources/css/custom.css", ":root { --kc-primary: #000; }\n".getBytes(),
            "resources/img/logo.svg", validSvg().getBytes(),
            "messages/messages_en.properties", "loginAccountTitle=Welcome\n".getBytes()
        ));

        ValidationResult r = validator.validateZip(zip);

        assertThat(r.isValid())
            .as("errors: %s", r.errors())
            .isTrue();
        assertThat(r.extractedFiles()).containsKey("theme.properties");
        assertThat(r.extractedFiles()).containsKey("resources/css/custom.css");
    }

    @Test
    void parentKeycloakBaseIsAlsoAccepted() throws Exception {
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak\n".getBytes()
        ));
        assertThat(validator.validateZip(zip).isValid()).isTrue();
    }

    // ---- structural rejects ------------------------------------------------

    @Test
    void emptyZip_isRejected() {
        ValidationResult r = validator.validateZip(new byte[0]);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code).contains("empty");
    }

    @Test
    void zipBeyondSizeCap_isRejected() throws Exception {
        // Build a zip that exceeds MAX_ZIP_BYTES (we pad with bytes that won't compress well).
        byte[] big = new byte[(int) (ThemeValidator.MAX_ZIP_BYTES + 100)];
        // Use a deterministic high-entropy pattern so the zip ALSO exceeds the cap (zip header + entry).
        for (int i = 0; i < big.length; i++) big[i] = (byte) (i * 31);
        // Wrap in an absolute byte array bigger than the cap — validator checks zip length first.
        ValidationResult r = validator.validateZip(big);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code)
            .contains("zip_too_large");
    }

    @Test
    void zipWithPathTraversal_isRejected() throws Exception {
        byte[] zip = zip(Map.of(
            "../etc/passwd", "ha\n".getBytes(),
            "theme.properties", "parent=keycloak.v2\n".getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code).contains("path_traversal");
    }

    @Test
    void zipWithAbsolutePath_isRejected() throws Exception {
        byte[] zip = zip(Map.of(
            "/etc/passwd", "ha\n".getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code).contains("path_traversal");
    }

    @Test
    void missingThemeProperties_isRejected() throws Exception {
        byte[] zip = zip(Map.of(
            "resources/css/custom.css", "/* ok */".getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code)
            .contains("missing_theme_properties");
    }

    @Test
    void wrongParentInThemeProperties_isRejected() throws Exception {
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=hacked\n".getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code)
            .contains("theme_properties_bad_parent");
    }

    // ---- extension allowlist -----------------------------------------------

    @Test
    void jsFile_isRejected() throws Exception {
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\n".getBytes(),
            "resources/js/evil.js", "alert(1)".getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code).contains("forbidden_extension");
    }

    @Test
    void htmlFile_isRejected() throws Exception {
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\n".getBytes(),
            "login.html", "<html></html>".getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code).contains("forbidden_extension");
    }

    @Test
    void ftlFile_isRejected() throws Exception {
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\n".getBytes(),
            "login.ftl", "<#assign x = 1 />".getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code).contains("forbidden_extension");
    }

    // ---- CSS scan ----------------------------------------------------------

    @Test
    void cssWithRemoteUrl_isRejected() throws Exception {
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\n".getBytes(),
            "resources/css/custom.css",
                "body { background: url(https://evil.com/pixel.png); }\n".getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code).contains("css_external_url");
    }

    @Test
    void cssWithProtocolRelativeUrl_isRejected() throws Exception {
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\n".getBytes(),
            "resources/css/custom.css",
                "body { background: url(//evil.com/pixel.png); }\n".getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code).contains("css_external_url");
    }

    @Test
    void cssWithImport_isRejected() throws Exception {
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\n".getBytes(),
            "resources/css/custom.css",
                "@import url('https://evil.com/x.css');\n body { color: red; }".getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code).contains("css_import_forbidden");
    }

    @Test
    void cssWithExpression_isRejected() throws Exception {
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\n".getBytes(),
            "resources/css/custom.css",
                "body { width: expression(alert(1)); }\n".getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code).contains("css_expression");
    }

    @Test
    void cssWithJavascriptUrl_isRejected() throws Exception {
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\n".getBytes(),
            "resources/css/custom.css",
                "body { background: url(javascript:alert(1)); }\n".getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code).contains("css_javascript_url");
    }

    @Test
    void cssWithRelativeUrl_isAccepted() throws Exception {
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\n".getBytes(),
            "resources/css/custom.css",
                "body { background: url('../img/logo.svg'); }\n".getBytes(),
            "resources/img/logo.svg", validSvg().getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.errors()).isEmpty();
    }

    // ---- SVG sanitization --------------------------------------------------

    @Test
    void svgWithScript_isSanitized() throws Exception {
        String evil = "<svg xmlns=\"http://www.w3.org/2000/svg\">"
            + "<script>alert(1)</script>"
            + "<circle cx=\"5\" cy=\"5\" r=\"4\" fill=\"red\"/>"
            + "</svg>";
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\n".getBytes(),
            "resources/img/logo.svg", evil.getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        // SVG sanitization: stripping a <script> is a warn-and-allow, NOT a reject.
        assertThat(r.isValid()).as("errors: %s", r.errors()).isTrue();
        String sanitized = new String(r.extractedFiles().get("resources/img/logo.svg"), StandardCharsets.UTF_8);
        assertThat(sanitized.toLowerCase()).doesNotContain("<script");
        assertThat(sanitized.toLowerCase()).contains("circle");
    }

    @Test
    void svgWithForeignObject_isRejected() throws Exception {
        String evil = "<svg xmlns=\"http://www.w3.org/2000/svg\">"
            + "<foreignObject><iframe src=\"https://evil.com\"></iframe></foreignObject>"
            + "</svg>";
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\n".getBytes(),
            "resources/img/logo.svg", evil.getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code).contains("svg_foreign_object");
    }

    @Test
    void svgWithRemoteHref_isRejected() throws Exception {
        String evil = "<svg xmlns=\"http://www.w3.org/2000/svg\">"
            + "<use xlink:href=\"https://evil.com/x.svg#thing\"/></svg>";
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\n".getBytes(),
            "resources/img/logo.svg", evil.getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code).contains("svg_remote_href");
    }

    // ---- properties --------------------------------------------------------

    @Test
    void propertiesWithScriptTag_isRejected() throws Exception {
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\n".getBytes(),
            "messages/messages_en.properties",
                "loginTitle=Welcome <script>alert(1)</script>\n".getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code)
            .contains("properties_forbidden_token");
    }

    @Test
    void propertiesWithOnclick_isRejected() throws Exception {
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\n".getBytes(),
            "messages/messages_en.properties",
                "loginTitle=<a onclick=alert(1)>Welcome</a>\n".getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code)
            .containsAnyOf("properties_event_handler", "properties_forbidden_token");
    }

    // ---- magic bytes -------------------------------------------------------

    @Test
    void pngWithWrongMagic_isRejected() throws Exception {
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\n".getBytes(),
            "resources/img/logo.png", "this is not a PNG".getBytes()
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.isValid()).isFalse();
        assertThat(r.errors()).extracting(ValidationResult.Error::code)
            .contains("magic_byte_mismatch");
    }

    @Test
    void pngWithCorrectMagic_isAccepted() throws Exception {
        byte[] png = new byte[16];
        png[0] = (byte) 0x89; png[1] = 0x50; png[2] = 0x4E; png[3] = 0x47;
        png[4] = 0x0D; png[5] = 0x0A; png[6] = 0x1A; png[7] = 0x0A;
        byte[] zip = zip(Map.of(
            "theme.properties", "parent=keycloak.v2\n".getBytes(),
            "resources/img/logo.png", png
        ));
        ValidationResult r = validator.validateZip(zip);
        assertThat(r.errors()).isEmpty();
    }

    // ---- helpers -----------------------------------------------------------

    private static byte[] zip(Map<String, byte[]> entries) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // LinkedHashMap-style traversal so entry order is deterministic.
        Map<String, byte[]> ordered = new LinkedHashMap<>(entries);
        try (ZipOutputStream zos = new ZipOutputStream(out)) {
            for (Map.Entry<String, byte[]> e : ordered.entrySet()) {
                zos.putNextEntry(new ZipEntry(e.getKey()));
                zos.write(e.getValue());
                zos.closeEntry();
            }
        }
        return out.toByteArray();
    }

    private static String validSvg() {
        return "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 32 32\">"
            + "<circle cx=\"16\" cy=\"16\" r=\"14\" fill=\"#000\"/></svg>";
    }
}
