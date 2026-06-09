package io.mcpmesh.auth.manager.email;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A small {@code <style>}-block → inline-{@code style}-attribute pass for
 * transactional email HTML. Many mail clients ignore {@code <style>} blocks;
 * inlining the declarations onto matching elements is the most portable way to
 * get consistent rendering.
 *
 * <p>Intentionally simple: it handles the flat selector forms our starter +
 * tenant templates use ({@code tag}, {@code .class}, {@code #id}, and
 * comma-separated lists of those). Existing inline {@code style} attributes win
 * over stylesheet declarations (cascade approximation: inline = highest). The
 * source {@code <style>} block is left in place so clients that DO honor it
 * still match.
 */
@Component
public class CssInliner {

    private static final Pattern RULE = Pattern.compile(
        "([^{}]+)\\{([^{}]*)\\}", Pattern.DOTALL);

    public String inline(String html) {
        if (html == null || html.isBlank()) return html;
        Document doc = Jsoup.parse(html);
        doc.outputSettings().prettyPrint(false);

        Elements styleTags = doc.select("style");
        for (Element style : styleTags) {
            applyStylesheet(doc, style.data());
        }
        return doc.outerHtml();
    }

    private void applyStylesheet(Document doc, String css) {
        if (css == null || css.isBlank()) return;
        String cleaned = css.replaceAll("/\\*.*?\\*/", " ");
        Matcher m = RULE.matcher(cleaned);
        while (m.find()) {
            String selectors = m.group(1).trim();
            String decls = m.group(2).trim();
            if (decls.isEmpty()) continue;
            // Skip at-rules (@media, @font-face, ...) — not safely inlinable.
            if (selectors.startsWith("@")) continue;
            for (String selector : selectors.split(",")) {
                String sel = selector.trim();
                if (sel.isEmpty() || !isSimpleSelector(sel)) continue;
                Elements matched;
                try {
                    matched = doc.select(sel);
                } catch (Exception e) {
                    continue;
                }
                for (Element el : matched) {
                    mergeStyle(el, decls);
                }
            }
        }
    }

    /** Only inline flat selectors we can safely resolve (tag / .class / #id). */
    private boolean isSimpleSelector(String sel) {
        return sel.matches("[a-zA-Z0-9_.#-]+");
    }

    /** Prepends stylesheet declarations; existing inline values keep priority. */
    private void mergeStyle(Element el, String stylesheetDecls) {
        String existing = el.attr("style").trim();
        List<String> existingProps = new ArrayList<>();
        for (String d : existing.split(";")) {
            int c = d.indexOf(':');
            if (c > 0) existingProps.add(d.substring(0, c).trim().toLowerCase());
        }
        StringBuilder merged = new StringBuilder();
        for (String d : stylesheetDecls.split(";")) {
            String decl = d.trim();
            if (decl.isEmpty()) continue;
            int c = decl.indexOf(':');
            if (c <= 0) continue;
            String prop = decl.substring(0, c).trim().toLowerCase();
            if (existingProps.contains(prop)) continue;  // inline wins
            merged.append(decl).append("; ");
        }
        if (merged.length() == 0) return;
        String combined = existing.isEmpty()
            ? merged.toString().trim()
            : merged + existing;
        el.attr("style", combined.trim());
    }
}
