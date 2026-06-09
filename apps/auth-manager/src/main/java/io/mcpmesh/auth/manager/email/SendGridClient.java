package io.mcpmesh.auth.manager.email;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Thin wrapper around the SendGrid v3 whitelabel-domains API. Uses Java's
 * built-in {@link HttpClient}; no external SDK.
 *
 * <p>Auth is via the platform SendGrid API key sourced from
 * {@link SmtpProperties#sendgridApiKey()}. When the key is absent, calls
 * throw {@link SendGridApiException} with a clean message so the caller
 * surfaces a 503-style error to the UI instead of an obscure NPE.
 *
 * <p>Throws {@link SendGridApiException} on any non-2xx response (the
 * SendGrid error body is propagated verbatim into the exception message).
 */
@Component
public class SendGridClient {

    private static final Logger log = LoggerFactory.getLogger(SendGridClient.class);
    private static final String API_BASE = "https://api.sendgrid.com/v3";

    private final HttpClient http = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build();
    private final ObjectMapper mapper = new ObjectMapper();
    private final SmtpProperties smtpProps;

    public SendGridClient(SmtpProperties smtpProps) {
        this.smtpProps = smtpProps;
    }

    public boolean isConfigured() {
        return smtpProps.hasSendgridApiKey();
    }

    /**
     * POST /v3/whitelabel/domains — registers a new whitelabel domain with
     * {@code automatic_security: true} (SendGrid auto-generates the 3 DNS
     * CNAMEs). Returns the created domain id + DNS records.
     *
     * <p>If the domain is already registered for this account, SendGrid returns
     * 409 — callers should fall back to {@link #findDomain(String)} + reuse.
     */
    public DomainAuthResult createDomain(String domain) {
        ObjectNode body = mapper.createObjectNode();
        body.put("domain", domain);
        body.put("automatic_security", true);
        body.put("default", false);
        HttpRequest req = baseBuilder(API_BASE + "/whitelabel/domains")
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
            .build();
        return parseDomain(send(req));
    }

    /**
     * GET /v3/whitelabel/domains?domain=&lt;domain&gt; — looks up an existing
     * domain by its bare name. Returns empty when no whitelabel domain matches.
     */
    public Optional<DomainAuthResult> findDomain(String domain) {
        String url = API_BASE + "/whitelabel/domains?domain="
            + URLEncoder.encode(domain, StandardCharsets.UTF_8);
        HttpRequest req = baseBuilder(url).GET().build();
        JsonNode body = send(req);
        if (!body.isArray() || body.isEmpty()) return Optional.empty();
        return Optional.of(parseDomain(body.get(0)));
    }

    /**
     * GET /v3/whitelabel/domains/{id} — re-fetches the cached state of a
     * previously-registered domain (including {@code valid} flag).
     */
    public DomainAuthResult getDomain(int domainId) {
        HttpRequest req = baseBuilder(API_BASE + "/whitelabel/domains/" + domainId)
            .GET().build();
        return parseDomain(send(req));
    }

    /**
     * POST /v3/whitelabel/domains/{id}/validate — asks SendGrid to verify the
     * CNAMEs now resolve, returning the updated {@code valid} flag.
     */
    public DomainAuthResult validateDomain(int domainId) {
        HttpRequest req = baseBuilder(API_BASE + "/whitelabel/domains/" + domainId + "/validate")
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString("{}"))
            .build();
        JsonNode resp = send(req);
        // The /validate endpoint returns {id, valid, validation_results}. Its
        // top-level `valid` is the AUTHORITATIVE just-computed result — the
        // domain record returned by GET /whitelabel/domains/{id} lags behind
        // and frequently still reports valid:false immediately after a
        // successful validate (its cached `valid` only flips on SendGrid's
        // side later). So we must read `valid` from THIS response, not from a
        // re-fetch. The GET is only used to recover the stable domain/dns
        // fields (name + CNAMEs) which the /validate body omits.
        int id = resp.path("id").isInt() ? resp.path("id").asInt() : domainId;
        DomainAuthResult record = getDomain(id);
        // Trust the validate response's `valid`; keep the GET's domain + cnames.
        return mergeValidateResult(resp, record);
    }

    /**
     * Merges the authoritative {@code valid} flag from a {@code /validate}
     * response with the stable {@code domain} + {@code cnames} from a domain
     * GET record. Package-private + static so the "validate's valid wins over
     * the stale GET valid" rule is unit-testable without live HTTP.
     */
    static DomainAuthResult mergeValidateResult(JsonNode validateResp, DomainAuthResult getRecord) {
        boolean valid = validateResp.path("valid").asBoolean(false);
        return new DomainAuthResult(getRecord.id(), getRecord.domain(), valid, getRecord.cnames());
    }

    // -- internals ------------------------------------------------------------

    /**
     * Parses a SendGrid whitelabel domain JSON object into our flat record.
     * The 3 CNAMEs live under {@code dns.{mail_cname,dkim1,dkim2}} as objects
     * with {@code host} + {@code data} (target) fields.
     */
    static DomainAuthResult parseDomain(JsonNode node) {
        int id = node.path("id").asInt(0);
        String domain = node.path("domain").asText(null);
        boolean valid = node.path("valid").asBoolean(false);
        List<DnsCname> cnames = new ArrayList<>();
        JsonNode dns = node.path("dns");
        addCname(cnames, dns, "mail_cname");
        addCname(cnames, dns, "dkim1");
        addCname(cnames, dns, "dkim2");
        return new DomainAuthResult(id, domain, valid, cnames);
    }

    private static void addCname(List<DnsCname> out, JsonNode dns, String key) {
        JsonNode n = dns.path(key);
        if (n.isMissingNode() || !n.isObject()) return;
        String host = n.path("host").asText(null);
        String target = n.path("data").asText(null);
        if (host != null && target != null) {
            out.add(new DnsCname(host, target));
        }
    }

    private HttpRequest.Builder baseBuilder(String url) {
        if (!smtpProps.hasSendgridApiKey()) {
            throw new SendGridApiException(
                "SendGrid API key is not configured (auth-manager.smtp.sendgrid-api-key / SENDGRID_API_KEY)");
        }
        return HttpRequest.newBuilder(URI.create(url))
            .header("Authorization", "Bearer " + smtpProps.sendgridApiKey())
            .header("Accept", "application/json")
            .timeout(Duration.ofSeconds(15));
    }

    private JsonNode send(HttpRequest req) {
        HttpResponse<String> response;
        try {
            response = http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            throw new SendGridApiException("SendGrid API call failed: " + e.getMessage(), e);
        }
        int code = response.statusCode();
        String bodyText = response.body() == null ? "" : response.body();
        if (code == 409) {
            throw new SendGridConflictException(bodyText);
        }
        if (code < 200 || code >= 300) {
            throw new SendGridApiException(
                "SendGrid API " + req.method() + " " + req.uri() + " returned " + code + ": " + bodyText);
        }
        try {
            return bodyText.isBlank() ? mapper.createObjectNode() : mapper.readTree(bodyText);
        } catch (IOException e) {
            throw new SendGridApiException("SendGrid API returned unparseable JSON: " + bodyText, e);
        }
    }

    // -- DTOs -----------------------------------------------------------------

    public record DnsCname(String host, String target) {}

    public record DomainAuthResult(int id, String domain, boolean valid, List<DnsCname> cnames) {}

    public static class SendGridApiException extends RuntimeException {
        public SendGridApiException(String message) { super(message); }
        public SendGridApiException(String message, Throwable cause) { super(message, cause); }
    }

    /**
     * 409 from SendGrid — typically "domain already registered". Callers use
     * this signal to fall back to {@link #findDomain(String)} + reuse the
     * existing id rather than failing the request.
     */
    public static class SendGridConflictException extends SendGridApiException {
        public SendGridConflictException(String body) {
            super("SendGrid returned 409 (conflict): " + body);
        }
    }
}
