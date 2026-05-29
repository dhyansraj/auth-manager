package io.mcpmesh.auth.manager.cloudflare;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
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
 * Thin HTTP wrapper around the Cloudflare v4 API for DNS-record + tunnel-ingress
 * management. Uses Java's built-in {@link HttpClient}; no external deps.
 *
 * <p>All POST/PUT bodies are JSON. Authorization is via Bearer token sourced
 * from {@link CloudflareProperties#apiToken()}.
 *
 * <p>Throws {@link CloudflareApiException} on any non-2xx response or
 * {@code "success": false} envelope. Callers in {@link CloudflareTunnelService}
 * catch + log; CF failures never fail tenant create/delete.
 */
@Component
public class CloudflareClient {

    private static final Logger log = LoggerFactory.getLogger(CloudflareClient.class);
    private static final String API_BASE = "https://api.cloudflare.com/client/v4";

    private final HttpClient http = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build();
    private final ObjectMapper mapper = new ObjectMapper();
    private final CloudflareProperties props;

    public CloudflareClient(CloudflareProperties props) {
        this.props = props;
    }

    /** GET /zones?name=<zoneName>. Returns the zone id if exists in our account, else empty. */
    public Optional<String> findZoneId(String zoneName) {
        String url = API_BASE + "/zones?name=" + enc(zoneName);
        JsonNode body = send(HttpRequest.newBuilder(URI.create(url)).GET());
        JsonNode result = body.path("result");
        if (result.isArray() && result.size() > 0) {
            return Optional.ofNullable(result.get(0).path("id").asText(null));
        }
        return Optional.empty();
    }

    /** GET /zones/{zoneId}/dns_records?type=CNAME&name=<recordName>. Returns record id if exists. */
    public Optional<String> findCnameRecordId(String zoneId, String recordName) {
        String url = API_BASE + "/zones/" + zoneId
            + "/dns_records?type=CNAME&name=" + enc(recordName);
        JsonNode body = send(HttpRequest.newBuilder(URI.create(url)).GET());
        JsonNode result = body.path("result");
        if (result.isArray() && result.size() > 0) {
            return Optional.ofNullable(result.get(0).path("id").asText(null));
        }
        return Optional.empty();
    }

    /** POST /zones/{zoneId}/dns_records — creates a proxied CNAME. */
    public String createCnameRecord(String zoneId, String name, String target, String comment) {
        String url = API_BASE + "/zones/" + zoneId + "/dns_records";
        ObjectNode payload = cnamePayload(name, target, comment, true);
        JsonNode body = send(HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(payload.toString())));
        return body.path("result").path("id").asText(null);
    }

    /**
     * POST /zones/{zoneId}/dns_records — creates a DNS-only (unproxied) CNAME.
     * Used for SendGrid DKIM CNAMEs, which MUST NOT be proxied through
     * Cloudflare (the proxy strips response headers + DNS-CNAME chains needed
     * by SendGrid's resolver).
     */
    public String createDnsOnlyCnameRecord(String zoneId, String name, String target, String comment) {
        String url = API_BASE + "/zones/" + zoneId + "/dns_records";
        ObjectNode payload = cnamePayload(name, target, comment, false);
        JsonNode body = send(HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(payload.toString())));
        return body.path("result").path("id").asText(null);
    }

    /** PUT /zones/{zoneId}/dns_records/{recordId} — updates existing (proxied). */
    public void updateCnameRecord(String zoneId, String recordId, String name, String target, String comment) {
        String url = API_BASE + "/zones/" + zoneId + "/dns_records/" + recordId;
        ObjectNode payload = cnamePayload(name, target, comment, true);
        send(HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString(payload.toString())));
    }

    /** DELETE /zones/{zoneId}/dns_records/{recordId}. */
    public void deleteDnsRecord(String zoneId, String recordId) {
        String url = API_BASE + "/zones/" + zoneId + "/dns_records/" + recordId;
        send(HttpRequest.newBuilder(URI.create(url)).DELETE());
    }

    /**
     * GET /accounts/{accountId}/cfd_tunnel/{tunnelId}/configurations.
     * Returns the ingress rules list. Each rule preserves its hostname
     * (which is null for the trailing catch-all) and service.
     */
    public List<IngressRule> getTunnelIngress() {
        String url = API_BASE + "/accounts/" + props.accountId()
            + "/cfd_tunnel/" + props.tunnelId() + "/configurations";
        JsonNode body = send(HttpRequest.newBuilder(URI.create(url)).GET());
        JsonNode ingress = body.path("result").path("config").path("ingress");
        List<IngressRule> rules = new ArrayList<>();
        if (ingress.isArray()) {
            for (JsonNode r : ingress) {
                String hostname = r.hasNonNull("hostname") ? r.get("hostname").asText() : null;
                String service = r.hasNonNull("service") ? r.get("service").asText() : null;
                rules.add(new IngressRule(hostname, service));
            }
        }
        return rules;
    }

    /**
     * PUT /accounts/{accountId}/cfd_tunnel/{tunnelId}/configurations.
     * Replaces ingress with full list. Caller is responsible for preserving
     * the trailing catch-all (hostname=null, service="http_status:404").
     */
    public void putTunnelIngress(List<IngressRule> rules) {
        String url = API_BASE + "/accounts/" + props.accountId()
            + "/cfd_tunnel/" + props.tunnelId() + "/configurations";
        ObjectNode root = mapper.createObjectNode();
        ObjectNode config = root.putObject("config");
        ArrayNode arr = config.putArray("ingress");
        for (IngressRule r : rules) {
            ObjectNode n = arr.addObject();
            if (r.hostname() != null) n.put("hostname", r.hostname());
            if (r.service() != null) n.put("service", r.service());
        }
        send(HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString(root.toString())));
    }

    /** Verify token is valid + active. Returns true if so. */
    public boolean verifyToken() {
        try {
            JsonNode body = send(HttpRequest.newBuilder(
                URI.create(API_BASE + "/user/tokens/verify")).GET());
            return body.path("success").asBoolean(false);
        } catch (Exception e) {
            log.warn("CloudflareClient.verifyToken: {}", e.getMessage());
            return false;
        }
    }

    private ObjectNode cnamePayload(String name, String target, String comment, boolean proxied) {
        ObjectNode payload = mapper.createObjectNode();
        payload.put("type", "CNAME");
        payload.put("name", name);
        payload.put("content", target);
        payload.put("proxied", proxied);
        payload.put("ttl", 1);
        if (comment != null) payload.put("comment", comment);
        return payload;
    }

    private JsonNode send(HttpRequest.Builder builder) {
        HttpRequest request = builder
            .header("Authorization", "Bearer " + props.apiToken())
            .header("Accept", "application/json")
            .timeout(Duration.ofSeconds(15))
            .build();
        HttpResponse<String> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            throw new CloudflareApiException("CF API call failed: " + e.getMessage(), e);
        }
        int code = response.statusCode();
        String bodyText = response.body() == null ? "" : response.body();
        if (code < 200 || code >= 300) {
            throw new CloudflareApiException(
                "CF API " + request.method() + " " + request.uri() + " returned " + code + ": " + bodyText);
        }
        JsonNode body;
        try {
            body = bodyText.isBlank() ? mapper.createObjectNode() : mapper.readTree(bodyText);
        } catch (IOException e) {
            throw new CloudflareApiException("CF API returned unparseable JSON: " + bodyText, e);
        }
        if (body.has("success") && !body.path("success").asBoolean(false)) {
            throw new CloudflareApiException(
                "CF API reported failure: " + body.path("errors").toString());
        }
        return body;
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    public record IngressRule(String hostname, String service) {}

    public static class CloudflareApiException extends RuntimeException {
        public CloudflareApiException(String message) { super(message); }
        public CloudflareApiException(String message, Throwable cause) { super(message, cause); }
    }
}
