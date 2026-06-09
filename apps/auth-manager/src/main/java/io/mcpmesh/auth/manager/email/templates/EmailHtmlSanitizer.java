package io.mcpmesh.auth.manager.email.templates;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.safety.Cleaner;
import org.jsoup.safety.Safelist;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * Permissive-but-safe HTML sanitizer for transactional <em>email</em> templates.
 *
 * <p>Unlike {@code BrandingHtmlSanitizer} (an OWASP policy tuned for Keycloak
 * LOGIN themes), email rendering happens inside the recipient's sandboxed mail
 * client and REQUIRES {@code <table>}-based layout, presentational attributes
 * ({@code cellpadding}/{@code bgcolor}/{@code align}/…), "bulletproof" table
 * buttons, and verbatim inline CSS. OWASP strips all of that. This sanitizer is
 * built on jsoup's {@link Cleaner} + a custom {@link Safelist}, which preserves
 * the {@code style} attribute's CSS verbatim while still dropping the dangerous
 * surface (scripts, event handlers, JS-protocol URLs, frames, forms, svg).
 *
 * <p>Policy summary:
 * <ul>
 *   <li><b>Permissive on structure/styling</b>: full table/layout/inline tag set
 *       plus presentational + style attributes applied to every element.</li>
 *   <li><b>Strict on scripts/links</b>: only {@code http https mailto tel} for
 *       {@code a[href]} and {@code http https cid data} for {@code img[src]};
 *       {@code <script>}, {@code on*} handlers, {@code <iframe>}/{@code <object>}/
 *       forms/{@code <svg>}/{@code <meta>}/{@code <link>} are dropped by
 *       omission.</li>
 *   <li><b>Defense-in-depth</b>: any surviving {@code <style>} block and every
 *       {@code style} attribute is scrubbed of remote {@code @import}s and CSS
 *       {@code expression(...)}.</li>
 * </ul>
 */
@Component
public class EmailHtmlSanitizer {

    /** {@code @import}, remote {@code url(...)} inside @import, and IE expression() — stripped from CSS. */
    private static final Pattern CSS_IMPORT =
        Pattern.compile("@import\\b[^;]*;?", Pattern.CASE_INSENSITIVE);
    private static final Pattern CSS_EXPRESSION =
        Pattern.compile("expression\\s*\\(", Pattern.CASE_INSENSITIVE);
    private static final Pattern CSS_JS_URL =
        Pattern.compile("url\\s*\\(\\s*['\"]?\\s*(?:javascript|vbscript)\\s*:",
            Pattern.CASE_INSENSITIVE);

    private final Cleaner cleaner;

    public EmailHtmlSanitizer() {
        this.cleaner = new Cleaner(buildSafelist());
    }

    private static Safelist buildSafelist() {
        Safelist safelist = new Safelist()
            // ---- Tables (essential for email layout) ----
            .addTags("table", "thead", "tbody", "tfoot", "tr", "td", "th",
                "caption", "col", "colgroup")
            // ---- Block-level / structural ----
            .addTags("div", "p", "span", "center", "br", "hr",
                "h1", "h2", "h3", "h4", "h5", "h6",
                "section", "header", "footer", "article", "aside",
                "blockquote", "pre", "code",
                "ul", "ol", "li", "dl", "dt", "dd",
                "figure", "figcaption")
            // ---- Inline formatting / media / links ----
            .addTags("a", "img", "b", "strong", "i", "em", "u", "s", "strike",
                "small", "big", "sub", "sup", "mark", "font", "abbr", "cite", "q")
            // ---- <style> block (CssInliner inlines it later) ----
            .addTags("style")
            .preserveRelativeLinks(false);

        // Broad presentational + styling attributes on EVERY element.
        String[] global = {
            "style", "class", "id", "title", "dir", "lang", "role",
            "align", "valign", "width", "height", "bgcolor", "background",
            "border", "cellpadding", "cellspacing", "colspan", "rowspan",
            "nowrap", "color", "face", "size"
        };
        safelist.addAttributes(":all", global);

        // Link-specific.
        safelist.addAttributes("a", "href", "target", "rel", "name");
        safelist.addProtocols("a", "href", "http", "https", "mailto", "tel");

        // Image-specific.
        safelist.addAttributes("img", "src", "alt", "width", "height", "border");
        safelist.addProtocols("img", "src", "http", "https", "cid", "data");

        return safelist;
    }

    /** Returns sanitized email HTML, or the empty string if input is null/blank. */
    public String sanitize(String html) {
        if (html == null) return "";
        String trimmed = html.strip();
        if (trimmed.isEmpty()) return "";

        Document dirty = Jsoup.parse(trimmed);
        // jsoup's Cleaner only traverses <body>; a top-level (or in-<head>)
        // <style> parks in <head> and would be dropped. Relocate every <style>
        // into the body BEFORE cleaning so it survives and the downstream
        // CssInliner (which reads <style> data) still finds it.
        for (Element style : dirty.head().select("style")) {
            dirty.body().prependChild(style);
        }

        Document clean = cleaner.clean(dirty);
        clean.outputSettings().prettyPrint(false);

        // Defense-in-depth: scrub CSS in surviving <style> blocks and style attrs.
        for (Element style : clean.select("style")) {
            String scrubbed = scrubCss(style.data());
            style.empty();
            style.appendChild(new org.jsoup.nodes.DataNode(scrubbed));
        }
        for (Element el : clean.select("[style]")) {
            el.attr("style", scrubCss(el.attr("style")));
        }

        return clean.body().html();
    }

    /** Removes {@code @import}, {@code expression(...)}, and JS-protocol urls from CSS. */
    private static String scrubCss(String css) {
        if (css == null || css.isEmpty()) return css;
        String out = CSS_IMPORT.matcher(css).replaceAll("");
        out = CSS_EXPRESSION.matcher(out).replaceAll("(");
        out = CSS_JS_URL.matcher(out).replaceAll("url(");
        return out;
    }
}
