package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.api.dto.CreateAppRequest.AppProfile;
import io.mcpmesh.auth.manager.domain.app.App;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.routing.RoutingPublisherBootstrap;
import io.mcpmesh.auth.manager.service.AppService;
import io.mcpmesh.auth.manager.service.TenantService;
import io.mcpmesh.auth.manager.service.UsermanagementBootstrap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * One-shot ops endpoints for repairing/backfilling KC state that older code
 * paths got wrong. Not part of the regular tenant lifecycle — operator runs
 * these manually after a platform fix lands. Each endpoint is idempotent so
 * re-runs are safe.
 */
@RestController
@RequestMapping("/api/v1/admin/repair")
public class AdminRepairController {

    private static final Logger log = LoggerFactory.getLogger(AdminRepairController.class);

    private final TenantService tenantService;
    private final AppService appService;
    private final KeycloakAdminService keycloak;
    private final RoutingPublisherBootstrap routingPublisher;

    public AdminRepairController(TenantService tenantService,
                                 AppService appService,
                                 KeycloakAdminService keycloak,
                                 RoutingPublisherBootstrap routingPublisher) {
        this.tenantService = tenantService;
        this.appService = appService;
        this.keycloak = keycloak;
        this.routingPublisher = routingPublisher;
    }

    /**
     * Scans every active tenant's backend-profile apps (CONFIDENTIAL_BACKEND,
     * SERVICE_ACCOUNT_ONLY) and ensures each has a per-backend client_scope on
     * the realm's {@code usermanagement} client so BFF-minted tokens carry
     * {@code aud:<backend-clientId>}.
     *
     * <p>Idempotent: re-running is a no-op for already-configured apps.
     * Returns a per-app result list so operators can spot failures.
     */
    @PostMapping("/usermanagement-audience")
    @PreAuthorize("@perms.has('TENANT_CREATE')")
    public Map<String, Object> repairUsermanagementAudience() {
        var report = new LinkedHashMap<String, Object>();
        var results = new ArrayList<Map<String, Object>>();

        List<Tenant> tenants = tenantService.list();
        for (Tenant t : tenants) {
            String realmName = t.getRealmName();
            if (realmName == null || realmName.isBlank()) continue;
            List<App> apps = appService.listByTenant(t.getId());
            for (App a : apps) {
                // Skip platform-managed apps -- usermanagement IS the audience
                // injector, not an audience target.
                if (UsermanagementBootstrap.CLIENT_SLUG.equals(a.getClientId())) continue;
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("realm", realmName);
                row.put("client", a.getClientId());
                try {
                    AppProfile profile = appService.detectProfile(realmName, a.getClientId());
                    if (profile != AppProfile.CONFIDENTIAL_BACKEND
                        && profile != AppProfile.SERVICE_ACCOUNT_ONLY) {
                        row.put("status", "skipped");
                        row.put("reason", "profile=" + profile.name());
                        results.add(row);
                        continue;
                    }
                    keycloak.ensureUsermanagementAudienceFor(realmName, a.getClientId());
                    row.put("status", "ok");
                    row.put("profile", profile.name());
                } catch (Exception e) {
                    log.warn("repairUsermanagementAudience: realm={} client={} failed: {}",
                        realmName, a.getClientId(), e.getMessage());
                    row.put("status", "error");
                    row.put("message", e.getMessage());
                }
                results.add(row);
            }
        }
        report.put("results", results);
        report.put("tenantsScanned", tenants.size());
        return report;
    }

    /**
     * Re-publishes every ACTIVE tenant's routing data ({@code host:*} hashes
     * and {@code route:*} keys) from Postgres into Redis. Same logic as the
     * boot-time {@link RoutingPublisherBootstrap}; exposed here so an
     * operator can repair Redis mid-operation (e.g. after a Redis pod
     * restart) without restarting auth-manager.
     *
     * <p>Idempotent: HSET + SET semantics make repeated calls a no-op
     * against a warm cache.
     */
    @PostMapping("/redis-routes")
    @PreAuthorize("@perms.has('TENANT_CREATE')")
    public Map<String, Object> repairRedisRoutes() {
        RoutingPublisherBootstrap.RepublishReport r = routingPublisher.republishAll();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("tenantsScanned", r.tenantsScanned());
        out.put("hostsPublished", r.hostsPublished());
        out.put("routesPublished", r.routesPublished());
        out.put("failures", r.failures());
        return out;
    }
}
