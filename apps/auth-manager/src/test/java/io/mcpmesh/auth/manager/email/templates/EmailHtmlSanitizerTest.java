package io.mcpmesh.auth.manager.email.templates;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the email-grade sanitizer keeps table layout, presentational
 * attributes, and inline CSS verbatim, while still dropping scripts, event
 * handlers, frames, and JS-protocol links.
 */
class EmailHtmlSanitizerTest {

    private final EmailHtmlSanitizer sanitizer = new EmailHtmlSanitizer();

    @Test
    void keepsTableLayout_presentationalAttrs_inlineCss_andTableButton() {
        String html = """
            <table cellpadding="0" cellspacing="0" align="center" bgcolor="#f4f5f7" width="600" border="0">
              <tr>
                <td valign="top" style="padding:24px; font-family:Arial,sans-serif; color:#111827;">
                  <table cellpadding="0" cellspacing="0">
                    <tr>
                      <td bgcolor="#4f46e5" align="center" style="border-radius:8px;">
                        <a href="https://acme.example/go" style="display:inline-block; padding:14px 28px; color:#ffffff; text-decoration:none; font-weight:600;">Accept</a>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
            """;
        String out = sanitizer.sanitize(html);

        // Structure preserved.
        assertThat(out).contains("<table");
        assertThat(out).contains("<td");
        // Presentational attributes preserved.
        assertThat(out).contains("cellpadding=\"0\"");
        assertThat(out).contains("cellspacing=\"0\"");
        assertThat(out).contains("align=\"center\"");
        assertThat(out).contains("bgcolor=\"#f4f5f7\"");
        assertThat(out).contains("valign=\"top\"");
        assertThat(out).contains("width=\"600\"");
        assertThat(out).contains("border=\"0\"");
        // Inline CSS preserved verbatim.
        assertThat(out).contains("padding:14px 28px");
        assertThat(out).contains("text-decoration:none");
        assertThat(out).contains("border-radius:8px");
        // Table button anchor survives with its http href.
        assertThat(out).contains("<a");
        assertThat(out).contains("href=\"https://acme.example/go\"");
    }

    @Test
    void keepsStyleBlock_andMustacheSectionAndVarTextTags() {
        String html = """
            <style>.cta { color:#fff; background-color:#4f46e5; }</style>
            <div>
              {{#inviterName}}<p>Invited by {{inviterName}}</p>{{/inviterName}}
              <p>Sent to {{recipientEmail}}</p>
            </div>
            """;
        String out = sanitizer.sanitize(html);

        assertThat(out).contains("<style");
        assertThat(out).contains("background-color:#4f46e5");
        // Mustache section + var tags in TEXT survive verbatim (no {{ neutering).
        assertThat(out).contains("{{#inviterName}}");
        assertThat(out).contains("{{/inviterName}}");
        assertThat(out).contains("{{inviterName}}");
        assertThat(out).contains("{{recipientEmail}}");
    }

    @Test
    void stripsScript_eventHandlers_iframe_andJavascriptHref() {
        String html = """
            <div onclick="steal()">
              <p>hi</p>
              <script>steal()</script>
              <iframe src="https://evil.example"></iframe>
              <a href="javascript:alert(1)">x</a>
            </div>
            """;
        String out = sanitizer.sanitize(html).toLowerCase();

        assertThat(out).doesNotContain("<script");
        assertThat(out).doesNotContain("onclick");
        assertThat(out).doesNotContain("<iframe");
        assertThat(out).doesNotContain("javascript:");
        // The benign text content survives.
        assertThat(out).contains("hi");
    }

    @Test
    void stripsRemoteImports_andExpression_fromStyleBlockAndAttr() {
        String html = """
            <style>@import url('https://evil.example/x.css'); .a { color:red; }</style>
            <p style="width:expression(alert(1)); color:blue;">x</p>
            """;
        String out = sanitizer.sanitize(html);

        assertThat(out).doesNotContain("@import");
        assertThat(out.toLowerCase()).doesNotContain("expression(");
        // Benign declarations remain.
        assertThat(out).contains("color:red");
        assertThat(out).contains("color:blue");
    }

    @Test
    void stripsForms_svg_andMetaLink() {
        String html = """
            <form action="https://evil.example"><input name="x"></form>
            <svg onload="alert(1)"></svg>
            <meta http-equiv="refresh" content="0">
            <link rel="stylesheet" href="https://evil.example/x.css">
            <p>kept</p>
            """;
        String out = sanitizer.sanitize(html).toLowerCase();

        assertThat(out).doesNotContain("<form");
        assertThat(out).doesNotContain("<input");
        assertThat(out).doesNotContain("<svg");
        assertThat(out).doesNotContain("<meta");
        assertThat(out).doesNotContain("<link");
        assertThat(out).contains("kept");
    }
}
