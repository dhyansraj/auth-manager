package io.mcpmesh.auth.manager.theme.branding;

import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.springframework.stereotype.Component;

/**
 * Tight allowlist sanitizer for tenant-supplied slot HTML.
 *
 * <p>The policy is intentionally narrower than what
 * {@link org.owasp.html.Sanitizers#FORMATTING} ships with: no scripts, no
 * event handlers, no JS-protocol URLs, no iframe/embed/object, no form
 * elements (the form is the kc.v2 card, not a slot). Inline styles ARE
 * allowed so operators can use {@code style="color: red"} for quick
 * decoration; if that turns out to be a vector we can drop it later.
 */
@Component
public class BrandingHtmlSanitizer {

    private final PolicyFactory policy;

    public BrandingHtmlSanitizer() {
        this.policy = new HtmlPolicyBuilder()
            // Block-level + structural
            .allowElements(
                "div", "section", "article", "header", "footer", "aside", "nav",
                "main", "p", "br", "hr",
                "h1", "h2", "h3", "h4", "h5", "h6",
                "ul", "ol", "li", "dl", "dt", "dd",
                "blockquote", "figure", "figcaption"
            )
            // Inline formatting
            .allowElements(
                "span", "strong", "em", "b", "i", "u", "small", "mark",
                "sub", "sup", "code", "pre", "kbd", "samp", "abbr", "cite",
                "q", "time"
            )
            // Media + links (images only — server-side sanitizer also blocks
            // JS-protocol via the URL filter below).
            .allowElements("a", "img", "picture", "source")
            // Globally-safe attributes
            .allowAttributes("id", "class", "title", "lang", "dir", "role",
                             "aria-label", "aria-hidden", "aria-labelledby",
                             "aria-describedby", "style").globally()
            .allowAttributes("href", "target", "rel").onElements("a")
            .allowAttributes("src", "alt", "width", "height", "loading",
                             "decoding", "srcset", "sizes").onElements("img")
            .allowAttributes("srcset", "sizes", "type", "media").onElements("source")
            // URL protocols — http/https for cross-tenant CDN assets and
            // data: for inline base64 images. NO javascript:, NO file:, etc.
            .allowUrlProtocols("https", "http", "data", "mailto")
            // Standalone elements are allowed without attributes.
            .allowStandardUrlProtocols()
            .toFactory();
    }

    /** Returns sanitized HTML, or the empty string if input is null/blank. */
    public String sanitize(String html) {
        if (html == null) return "";
        String trimmed = html.strip();
        if (trimmed.isEmpty()) return "";
        return policy.sanitize(trimmed);
    }
}
