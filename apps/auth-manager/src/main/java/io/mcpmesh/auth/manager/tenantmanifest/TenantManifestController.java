package io.mcpmesh.auth.manager.tenantmanifest;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Phase 1 read-only manifest export. Returns the tenant's permissions catalog
 * and composite roles as YAML (default) or JSON. Format is chosen by
 * {@code ?format=yaml|json} (explicit wins) or the {@code Accept} header
 * (falls back to YAML).
 *
 * <p>Phase 2 adds {@code POST /manifest:apply} for pushing changes to KC.
 */
@RestController
@RequestMapping("/api/v1/tenants/{slug}")
public class TenantManifestController {

    /** Common MIME for YAML. Spring 6 doesn't ship a constant for this. */
    public static final String APPLICATION_YAML_VALUE = "application/yaml";
    public static final MediaType APPLICATION_YAML = MediaType.parseMediaType(APPLICATION_YAML_VALUE);

    private final TenantManifestService service;
    private final TenantManifestApplyService applyService;
    private final ObjectMapper yamlMapper;
    private final ObjectMapper jsonMapper;

    public TenantManifestController(TenantManifestService service,
                                    TenantManifestApplyService applyService) {
        this.service = service;
        this.applyService = applyService;
        YAMLFactory yf = new YAMLFactory()
            .disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER)
            // Match the human-friendly shape from the spec: unquoted strings
            // when safe (id/name values like BOOKING_VIEW_OWN read clean), and
            // ISO-8601 instants serialized as plain strings (JavaTimeModule).
            .enable(YAMLGenerator.Feature.MINIMIZE_QUOTES)
            // Indent list items two spaces under their parent key so
            // top-level lists render as "  - id:" instead of "- id:".
            .enable(YAMLGenerator.Feature.INDENT_ARRAYS_WITH_INDICATOR);
        this.yamlMapper = new ObjectMapper(yf)
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);
        this.jsonMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    @GetMapping("/manifest")
    @PreAuthorize("@perms.hasOnTenant(#slug, 'MANIFEST_APPLY')")
    public ResponseEntity<String> get(
        @PathVariable String slug,
        @RequestParam(name = "format", required = false) String format,
        @RequestHeader(value = HttpHeaders.ACCEPT, required = false) String accept
    ) throws Exception {
        TenantManifest manifest = service.generate(slug);
        boolean json = wantsJson(format, accept);
        if (json) {
            String body = jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(manifest);
            return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
        }
        String body = yamlMapper.writeValueAsString(manifest);
        return ResponseEntity.ok()
            .contentType(APPLICATION_YAML)
            .body(body);
    }

    /**
     * Apply a manifest to Keycloak. Accepts JSON or YAML in the body (chosen
     * by Content-Type). The response is always JSON {@link ApplyResult}.
     *
     * <p>HTTP semantics:
     * <ul>
     *   <li>200 on successful apply, no-op, or dry-run</li>
     *   <li>409 when {@code applyRoles=true}, the stored hash differs from the
     *       current KC role state, and {@code force=false}. Caller must
     *       re-export, reconcile, and retry with {@code force=true}.</li>
     *   <li>400 on malformed body or references to non-existent KC clients /
     *       missing permission IDs</li>
     * </ul>
     */
    @PostMapping(path = "/manifest:apply",
                 consumes = {MediaType.APPLICATION_JSON_VALUE, APPLICATION_YAML_VALUE},
                 produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("@perms.hasOnTenant(#slug, 'MANIFEST_APPLY')")
    public ResponseEntity<ApplyResult> apply(
        @PathVariable String slug,
        @RequestBody byte[] body,
        @RequestHeader(value = HttpHeaders.CONTENT_TYPE, required = false) String contentType,
        @RequestParam(name = "applyRoles", defaultValue = "false") boolean applyRoles,
        @RequestParam(name = "force", defaultValue = "false") boolean force,
        @RequestParam(name = "dryRun", defaultValue = "false") boolean dryRun,
        Authentication auth
    ) throws Exception {
        TenantManifest manifest = parseManifest(body, contentType);
        try {
            ApplyResult result = applyService.apply(
                slug, manifest, applyRoles, force, dryRun, principal(auth));
            return ResponseEntity.ok(result);
        } catch (TenantManifestApplyService.TripwireException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(e.result());
        }
    }

    private TenantManifest parseManifest(byte[] body, String contentType) {
        if (body == null || body.length == 0) {
            throw new IllegalArgumentException("Empty request body");
        }
        boolean yaml = contentType != null && contentType.toLowerCase().contains("yaml");
        try {
            return (yaml ? yamlMapper : jsonMapper).readValue(body, TenantManifest.class);
        } catch (Exception e) {
            throw new IllegalArgumentException(
                "Failed to parse manifest body as " + (yaml ? "YAML" : "JSON")
                    + ": " + e.getMessage());
        }
    }

    /**
     * Explicit {@code ?format=} wins. Otherwise an {@code Accept} header that
     * names JSON ahead of YAML chooses JSON. Default is YAML.
     */
    private static boolean wantsJson(String format, String accept) {
        if (format != null && !format.isBlank()) {
            return "json".equalsIgnoreCase(format.trim());
        }
        if (accept == null || accept.isBlank()) return false;
        String lower = accept.toLowerCase();
        boolean mentionsJson = lower.contains("application/json");
        boolean mentionsYaml = lower.contains("yaml");
        if (mentionsJson && !mentionsYaml) return true;
        return false;
    }

    private static String principal(Authentication auth) {
        if (auth instanceof JwtAuthenticationToken jwtAuth) {
            Jwt jwt = jwtAuth.getToken();
            String pref = jwt.getClaimAsString("preferred_username");
            return pref != null ? pref : jwt.getSubject();
        }
        return "system";
    }
}
