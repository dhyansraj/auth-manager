package io.mcpmesh.auth.manager.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.mcpmesh.auth.manager.api.dto.AccessManifest;
import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.app.App;
import io.mcpmesh.auth.manager.domain.app.AppManifest;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.persistence.AppManifestRepository;
import io.mcpmesh.auth.manager.persistence.AppRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
@Transactional
public class ManifestService {

    private static final Logger log = LoggerFactory.getLogger(ManifestService.class);

    private static final String SYSTEM_ACTOR = "system";
    private static final ActorKind SYSTEM_KIND = ActorKind.SERVICE;

    private final AppManifestRepository manifestRepo;
    private final AppRepository appRepo;
    private final TenantService tenants;
    private final KeycloakAdminService keycloak;
    private final AuditService audit;

    private final ObjectMapper objectMapper;

    public ManifestService(AppManifestRepository manifestRepo, AppRepository appRepo,
                           TenantService tenants, KeycloakAdminService keycloak,
                           AuditService audit) {
        this.manifestRepo = manifestRepo;
        this.appRepo = appRepo;
        this.tenants = tenants;
        this.keycloak = keycloak;
        this.audit = audit;
        this.objectMapper = new ObjectMapper()
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
    }

    /**
     * Apply a manifest to an app's Keycloak client. Idempotent on hash:
     * reapplying the same body returns the existing record without touching
     * Keycloak.
     */
    public ApplyResult apply(UUID tenantId, UUID appId, AccessManifest manifest, String actor) {
        Tenant tenant = tenants.get(tenantId);
        App app = appRepo.findById(appId)
            .filter(a -> a.getTenantId().equals(tenantId))
            .orElseThrow(() -> new io.mcpmesh.auth.manager.service.exception.AppNotFoundException(appId.toString()));

        String hash = canonicalHash(manifest);

        // Idempotency check: identical hash = no-op.
        var existing = manifestRepo.findByAppIdAndHash(appId, hash);
        if (existing.isPresent()) {
            log.info("Manifest apply for app {} is a no-op (hash {} matches version {})",
                     app.getSlug(), hash, existing.get().getVersion());
            return new ApplyResult(existing.get(), true);
        }

        // For v1 we ONLY support the FIRST apply (clean slate). Subsequent applies
        // with different content require diff/update semantics, which is deferred.
        int currentVersion = manifestRepo.maxVersionForApp(appId);
        if (currentVersion > 0) {
            var ex = new UnsupportedOperationException(
                "Manifest update (version > 1) not yet supported. Delete + recreate app for now.");
            audit.recordFailure(SYSTEM_ACTOR, SYSTEM_KIND, tenantId,
                "app.apply", "app", appId.toString(),
                Map.of("hash", hash, "newVersion", currentVersion + 1),
                ex,
                Map.of("reason", "update_not_supported"));
            throw ex;
        }

        // Apply to Keycloak.
        String realmName = tenant.getRealmName();
        String clientUuid = keycloak.findClientUuid(realmName, app.getClientId())
            .orElseThrow(() -> new IllegalStateException(
                "Keycloak client missing for app " + app.getSlug() + " in realm " + realmName));

        try {
            applyToKeycloak(realmName, clientUuid, app.getClientId(), manifest);
        } catch (Exception e) {
            audit.recordFailure(SYSTEM_ACTOR, SYSTEM_KIND, tenantId,
                "app.apply", "app", appId.toString(),
                manifest,
                e,
                Map.of("reason", "keycloak_apply_failed", "hash", hash));
            throw new RuntimeException("Manifest apply failed: " + e.getMessage(), e);
        }

        // Persist manifest row.
        @SuppressWarnings("unchecked")
        Map<String, Object> manifestJson = objectMapper.convertValue(manifest, Map.class);
        String yaml = serializeJsonForStorage(manifest);
        AppManifest saved = manifestRepo.save(
            new AppManifest(appId, currentVersion + 1, yaml, manifestJson, hash,
                SYSTEM_ACTOR));

        audit.recordSuccess(SYSTEM_ACTOR, SYSTEM_KIND, tenantId,
            "app.apply", "app", appId.toString(),
            manifest,
            Map.of("hash", hash, "version", saved.getVersion(),
                   "rolesCount", manifest.roles().size(),
                   "resourcesCount", manifest.resources().size()));

        return new ApplyResult(saved, false);
    }

    private void applyToKeycloak(String realmName, String clientUuid,
                                 String oidcClientId, AccessManifest m) {
        // 1. Enable authz services on the client.
        keycloak.enableAuthz(realmName, clientUuid);

        // 2. Create all client roles.
        for (String role : m.roles()) {
            keycloak.createClientRole(realmName, clientUuid, role);
        }

        // 3. Create all unique scopes (union across resources).
        Set<String> allScopes = new HashSet<>();
        for (var r : m.resources()) allScopes.addAll(r.scopes());
        for (String scope : allScopes) {
            keycloak.createAuthzScope(realmName, clientUuid, scope);
        }

        // 4. Create resources with their scopes.
        for (var r : m.resources()) {
            keycloak.createAuthzResource(realmName, clientUuid, r.name(), new HashSet<>(r.scopes()));
        }

        // 5. Role policies + scope permissions.
        // For each role -> create a role policy; for each (resource, scopes) entry
        // under that role -> create a scope permission that grants the policy
        // those scopes on that resource.
        for (var entry : m.rolePermissions().entrySet()) {
            String role = entry.getKey();
            String policyName = "policy-" + role;
            String policyId = keycloak.createRolePolicy(
                realmName, clientUuid, oidcClientId, policyName, role);

            for (var rp : entry.getValue()) {
                String permName = "perm-" + role + "-" + rp.resource();
                keycloak.createScopePermission(realmName, clientUuid, permName,
                    rp.resource(), new HashSet<>(rp.scopes()), Set.of(policyId));
            }
        }
    }

    @Transactional(readOnly = true)
    public List<AppManifest> listForApp(UUID tenantId, UUID appId) {
        tenants.get(tenantId);
        appRepo.findById(appId)
            .filter(a -> a.getTenantId().equals(tenantId))
            .orElseThrow(() -> new io.mcpmesh.auth.manager.service.exception.AppNotFoundException(appId.toString()));
        return manifestRepo.findByAppIdOrderByVersionDesc(appId);
    }

    private String canonicalHash(AccessManifest m) {
        try {
            byte[] bytes = objectMapper.writeValueAsBytes(m);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(bytes));
        } catch (JsonProcessingException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to compute manifest hash", e);
        }
    }

    private String serializeJsonForStorage(AccessManifest m) {
        try {
            return objectMapper.writeValueAsString(m);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize manifest", e);
        }
    }

    public record ApplyResult(AppManifest manifest, boolean noOp) {}
}
