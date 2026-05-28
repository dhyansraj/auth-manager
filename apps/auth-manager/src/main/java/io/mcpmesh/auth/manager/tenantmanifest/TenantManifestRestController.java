package io.mcpmesh.auth.manager.tenantmanifest;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import io.mcpmesh.auth.manager.domain.app.App;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.AppRepository;
import io.mcpmesh.auth.manager.service.TenantService;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
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

import java.util.UUID;

/**
 * UUID-keyed tenant manifest endpoints used by the admin-ui's Permissions tab
 * for round-trip Download/Upload. Companion to the slug-keyed
 * {@link TenantManifestController} (whose endpoints predate the UUID-first
 * convention adopted in {@code TenantController}). The two controllers share
 * the same underlying services so the behavior matches exactly.
 *
 * <p>Guards mirror the UI gates:
 * <ul>
 *   <li>GET → {@code TENANT_VIEW} (read tier, same as audit + tenant detail)</li>
 *   <li>POST → {@code PERMISSIONS_EDIT} (matches the UI gate on the
 *       Permissions tab)</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/v1/tenants/{id}")
public class TenantManifestRestController {

    /** Common MIME for YAML. Spring 6 doesn't ship a constant for this. */
    public static final String APPLICATION_YAML_VALUE = "application/yaml";
    public static final String APPLICATION_X_YAML_VALUE = "application/x-yaml";
    public static final String TEXT_YAML_VALUE = "text/yaml";

    private static final Logger log = LoggerFactory.getLogger(TenantManifestRestController.class);

    private final TenantService tenants;
    private final TenantManifestService service;
    private final TenantManifestApplyService applyService;
    private final AppRepository appRepo;
    @Nullable private final Keycloak admin;
    private final ObjectMapper yamlMapper;

    public TenantManifestRestController(TenantService tenants,
                                        TenantManifestService service,
                                        TenantManifestApplyService applyService,
                                        AppRepository appRepo,
                                        @Nullable Keycloak admin) {
        this.tenants = tenants;
        this.service = service;
        this.applyService = applyService;
        this.appRepo = appRepo;
        this.admin = admin;
        YAMLFactory yf = new YAMLFactory()
            .disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER)
            .enable(YAMLGenerator.Feature.MINIMIZE_QUOTES)
            .enable(YAMLGenerator.Feature.INDENT_ARRAYS_WITH_INDICATOR);
        this.yamlMapper = new ObjectMapper(yf)
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    /**
     * Download the tenant's current manifest as YAML. Filename is the tenant's
     * slug so re-uploads round-trip cleanly. Operators get a starter (commented
     * skeleton with the tenant's client_id pre-filled) instead of an empty file
     * when the tenant has no permissions/roles configured yet.
     */
    @GetMapping(path = "/manifest", produces = APPLICATION_X_YAML_VALUE)
    @PreAuthorize("@perms.hasOnTenantId(#id, 'TENANT_VIEW')")
    public ResponseEntity<String> download(@PathVariable UUID id) throws Exception {
        Tenant tenant = tenants.get(id);
        String slug = tenant.getSlug();
        TenantManifest manifest = service.generate(slug);
        String firstBackendClientId = firstBackendClientId(tenant);
        String body = TenantManifestYamlRenderer.render(yamlMapper, tenant, manifest, firstBackendClientId);
        String filename = slug + "-manifest.yaml";
        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"" + filename + "\"")
            .contentType(MediaType.parseMediaType(APPLICATION_X_YAML_VALUE))
            .body(body);
    }

    /**
     * Apply an operator-uploaded manifest YAML to KC. Accepts any of the
     * common YAML content types plus {@code text/plain} (file pickers often
     * default to that for .yaml files). Returns the apply diff as JSON.
     *
     * @param applyRoles defaults TRUE here (matches the admin-ui's wizard
     *                   contract — operators uploading via UI expect roles
     *                   to materialize, not just permissions).
     */
    @PostMapping(path = "/manifest:apply",
                 consumes = {APPLICATION_YAML_VALUE, APPLICATION_X_YAML_VALUE,
                             TEXT_YAML_VALUE, MediaType.TEXT_PLAIN_VALUE,
                             MediaType.APPLICATION_OCTET_STREAM_VALUE},
                 produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("@perms.hasOnTenantId(#id, 'PERMISSIONS_EDIT')")
    public ResponseEntity<ApplyResult> apply(
        @PathVariable UUID id,
        @RequestBody byte[] body,
        @RequestHeader(value = HttpHeaders.CONTENT_TYPE, required = false) String contentType,
        @RequestParam(name = "applyRoles", defaultValue = "true") boolean applyRoles,
        @RequestParam(name = "force", defaultValue = "false") boolean force,
        @RequestParam(name = "dryRun", defaultValue = "false") boolean dryRun,
        Authentication auth
    ) {
        Tenant tenant = tenants.get(id);
        TenantManifest manifest = parseManifest(body);
        try {
            ApplyResult result = applyService.apply(
                tenant.getSlug(), manifest, applyRoles, force, dryRun, principal(auth));
            return ResponseEntity.ok(result);
        } catch (TenantManifestApplyService.TripwireException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(e.result());
        }
    }

    private TenantManifest parseManifest(byte[] body) {
        if (body == null || body.length == 0) {
            throw new IllegalArgumentException("Empty request body");
        }
        try {
            return yamlMapper.readValue(body, TenantManifest.class);
        } catch (Exception e) {
            throw new IllegalArgumentException(
                "Failed to parse manifest body as YAML: " + e.getMessage());
        }
    }

    /**
     * Best-effort lookup for a CONFIDENTIAL_BACKEND or SERVICE_ACCOUNT_ONLY app
     * client id, used to pre-fill the starter manifest's example permission.
     * Returns null on any failure — the renderer falls back to a placeholder.
     */
    private String firstBackendClientId(Tenant tenant) {
        if (admin == null) return null;
        try {
            String realmName = tenant.getRealmName();
            if (realmName == null) return null;
            for (App a : appRepo.findByTenantIdOrderByCreatedAtDesc(tenant.getId())) {
                if ("usermanagement".equals(a.getSlug())) continue;
                var matches = admin.realm(realmName).clients().findByClientId(a.getClientId());
                if (matches.isEmpty()) continue;
                ClientRepresentation c = matches.get(0);
                if (Boolean.TRUE.equals(c.isPublicClient())) continue;
                return a.getClientId();
            }
        } catch (Exception e) {
            log.debug("firstBackendClientId({}) lookup failed: {}",
                tenant.getSlug(), e.getMessage());
        }
        return null;
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
