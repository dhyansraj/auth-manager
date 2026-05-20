package io.mcpmesh.auth.manager.service;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.app.App;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.domain.tenant.TenantStatus;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.persistence.AppRepository;
import io.mcpmesh.auth.manager.service.exception.AppConflictException;
import io.mcpmesh.auth.manager.service.exception.AppNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Transactional
public class AppService {

    private static final Logger log = LoggerFactory.getLogger(AppService.class);

    private static final String SYSTEM_ACTOR = "system";
    private static final ActorKind SYSTEM_KIND = ActorKind.SERVICE;

    private final AppRepository repo;
    private final TenantService tenants;
    private final KeycloakAdminService keycloak;
    private final AuditService audit;

    public AppService(
        AppRepository repo,
        TenantService tenants,
        KeycloakAdminService keycloak,
        AuditService audit
    ) {
        this.repo = repo;
        this.tenants = tenants;
        this.keycloak = keycloak;
        this.audit = audit;
    }

    /**
     * Creates an OIDC client in the tenant's realm and persists an App row.
     * Returns the created App and the client secret (operator-visible once).
     */
    public AppCreationResult create(UUID tenantId, String slug, String displayName, String actor) {
        Tenant tenant = tenants.get(tenantId);  // 404 if not found / deleted
        if (tenant.getStatus() != TenantStatus.ACTIVE) {
            throw new IllegalStateException(
                "Cannot create app in tenant with status " + tenant.getStatus());
        }
        if (repo.existsByTenantIdAndSlug(tenantId, slug)) {
            audit.recordFailure(SYSTEM_ACTOR, SYSTEM_KIND, tenantId,
                "app.create", "app", null,
                Map.of("tenantSlug", tenant.getSlug(), "appSlug", slug),
                new AppConflictException(tenant.getSlug(), slug),
                Map.of("reason", "slug_conflict"));
            throw new AppConflictException(tenant.getSlug(), slug);
        }

        String realmName = tenant.getRealmName();
        String clientUuid;
        try {
            // Idempotency: if a previous failed attempt already created the KC client,
            // look it up rather than failing.
            clientUuid = keycloak.findClientUuid(realmName, slug)
                .orElseGet(() -> keycloak.createClient(realmName, slug, displayName));
        } catch (Exception e) {
            audit.recordFailure(SYSTEM_ACTOR, SYSTEM_KIND, tenantId,
                "app.create", "app", null,
                Map.of("tenantSlug", tenant.getSlug(), "appSlug", slug),
                e,
                Map.of("reason", "keycloak_create_failed"));
            throw new RuntimeException("Keycloak client creation failed: " + e.getMessage(), e);
        }

        App app = repo.save(new App(tenantId, slug, displayName, slug));
        String secret = keycloak.getClientSecret(realmName, clientUuid);

        audit.recordSuccess(SYSTEM_ACTOR, SYSTEM_KIND, tenantId,
            "app.create", "app", app.getId().toString(),
            Map.of("tenantSlug", tenant.getSlug(), "appSlug", slug),
            Map.of("clientId", slug, "realm", realmName));

        return new AppCreationResult(app, secret);
    }

    @Transactional(readOnly = true)
    public List<App> listByTenant(UUID tenantId) {
        tenants.get(tenantId);  // 404 if tenant gone
        return repo.findByTenantIdOrderByCreatedAtDesc(tenantId);
    }

    @Transactional(readOnly = true)
    public App get(UUID tenantId, UUID appId) {
        return repo.findById(appId)
            .filter(a -> a.getTenantId().equals(tenantId))
            .orElseThrow(() -> new AppNotFoundException(appId.toString()));
    }

    public void delete(UUID tenantId, UUID appId, String actor) {
        Tenant tenant = tenants.get(tenantId);
        App app = get(tenantId, appId);

        try {
            keycloak.findClientUuid(tenant.getRealmName(), app.getClientId())
                .ifPresent(uuid -> keycloak.deleteClient(tenant.getRealmName(), uuid));
        } catch (Exception e) {
            log.error("Keycloak client delete failed for app {}; removing DB row anyway",
                      app.getSlug(), e);
        }
        repo.delete(app);

        audit.recordSuccess(SYSTEM_ACTOR, SYSTEM_KIND, tenantId,
            "app.delete", "app", appId.toString(),
            null,
            Map.of("tenantSlug", tenant.getSlug(), "appSlug", app.getSlug()));
    }

    public record AppCreationResult(App app, String clientSecret) {}
}
