package io.mcpmesh.auth.manager.service;

import io.mcpmesh.auth.manager.api.dto.HostnameAssignment;
import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.domain.tenant.TenantHostname;
import io.mcpmesh.auth.manager.domain.tenant.TenantStatus;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.persistence.TenantHostnameRepository;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.routing.RoutingConfigService;
import io.mcpmesh.auth.manager.routing.RoutingTableService;
import io.mcpmesh.auth.manager.service.exception.TenantConflictException;
import io.mcpmesh.auth.manager.service.exception.TenantNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Transactional
public class TenantService {

    private static final Logger log = LoggerFactory.getLogger(TenantService.class);

    private static final String SYSTEM_ACTOR = "system";
    private static final ActorKind SYSTEM_KIND = ActorKind.SERVICE;

    private final TenantRepository repo;
    private final TenantHostnameRepository hostnameRepo;
    private final KeycloakAdminService keycloak;
    private final RoutingTableService routingTable;
    private final RoutingConfigService routingConfig;
    private final AuditService audit;

    public TenantService(
        TenantRepository repo,
        TenantHostnameRepository hostnameRepo,
        KeycloakAdminService keycloak,
        RoutingTableService routingTable,
        RoutingConfigService routingConfig,
        AuditService audit
    ) {
        this.repo = repo;
        this.hostnameRepo = hostnameRepo;
        this.keycloak = keycloak;
        this.routingTable = routingTable;
        this.routingConfig = routingConfig;
        this.audit = audit;
    }

    /**
     * Creates a tenant row and synchronously provisions its Keycloak realm.
     *
     * <p>The DB row is always saved (even if the KC call fails) so operators
     * have a record to retry against — see {@link #retryProvisioning(UUID, String)}.
     * On KC failure the tenant is persisted with status {@link TenantStatus#FAILED};
     * the HTTP layer still returns 201 because the tenant <em>resource</em> was
     * created. Callers must inspect {@code status} in the response to confirm
     * the realm is live.
     *
     * <p>Hostnames are persisted in DB BEFORE realm provisioning so that a
     * retry can re-publish them to Redis from the durable source.
     *
     * <p>TODO: dedicated management endpoints (POST/DELETE
     * {@code /tenants/{id}/hostnames}) are deferred — for now hostnames are
     * declared only at tenant create time.
     */
    public Tenant create(
        String slug,
        String displayName,
        Map<String, Object> settings,
        List<HostnameAssignment> hostnames,
        String actor
    ) {
        Tenant t;
        var existing = repo.findBySlug(slug);
        boolean resurrected = false;
        if (existing.isPresent()) {
            Tenant prior = existing.get();
            if (prior.isDeleted()) {
                // Resurrect: same UUID, history preserved, re-provision realm.
                log.info("Resurrecting previously-deleted tenant slug={} id={}", slug, prior.getId());
                prior.resurrect(displayName, settings);
                // Existing routingConfig is preserved across resurrection.
                t = repo.save(prior);
                // Clear any stale hostname rows from the prior life; replace with the new set
                hostnameRepo.deleteByTenantId(t.getId());
                resurrected = true;
            } else {
                // Active conflict -- no tenant row exists, but the attempt is auditable.
                var conflictPayload = createPayload(slug, displayName, settings, hostnames);
                audit.recordFailure(SYSTEM_ACTOR, SYSTEM_KIND, null,
                    "tenant.create", "tenant", null,
                    conflictPayload,
                    new TenantConflictException(slug),
                    Map.of("reason", "slug_conflict", "slug", slug));
                throw new TenantConflictException(slug);
            }
        } else {
            Tenant newTenant = new Tenant(slug, displayName, actor, settings);
            // routing_config is NOT NULL in the schema; seed with conventional
            // defaults so the initial INSERT succeeds. The post-persist
            // replaceForTenant below is what actually publishes to Redis +
            // emits the routes.apply audit event.
            newTenant.setRoutingConfig(routingConfig.defaultFor(slug));
            t = repo.save(newTenant);
        }

        if (hostnames != null) {
            for (HostnameAssignment h : hostnames) {
                hostnameRepo.save(new TenantHostname(h.host(), t.getId(), h.backend()));
            }
        }
        Tenant after = provisionRealm(t);

        var payload = createPayload(slug, displayName, settings, hostnames);
        Map<String, Object> details = new java.util.LinkedHashMap<>();
        details.put("slug", slug);
        details.put("status", after.getStatus().name());
        details.put("realm", after.getRealmName());
        details.put("hostnameCount", hostnames == null ? 0 : hostnames.size());
        if (resurrected) {
            details.put("resurrected", true);
        }

        if (after.getStatus() == TenantStatus.ACTIVE) {
            audit.recordSuccess(SYSTEM_ACTOR, SYSTEM_KIND, after.getId(),
                "tenant.create", "tenant", after.getId().toString(),
                payload, details);
        } else {
            audit.recordFailure(SYSTEM_ACTOR, SYSTEM_KIND, after.getId(),
                "tenant.create", "tenant", after.getId().toString(),
                payload,
                new RuntimeException("Provisioning ended in status " + after.getStatus()),
                details);
        }

        // Publish the (default for fresh; preserved for resurrected) routing
        // config to Redis and emit the routes.apply audit event. This runs
        // unconditionally so even a FAILED tenant still has its rules visible
        // to operators inspecting Redis.
        try {
            routingConfig.replaceForTenant(slug, after.getRoutingConfig());
        } catch (Exception e) {
            log.error("Routing config publish failed for new tenant {}; recoverable via PUT /routes",
                      slug, e);
        }
        return after;
    }

    /**
     * Re-attempts realm provisioning for a tenant in {@link TenantStatus#FAILED}.
     * No-op (returns current state) for tenants already ACTIVE.
     * Throws if the tenant is in any other status (PENDING, SUSPENDED, DELETED).
     *
     * <p>Also republishes the tenant's hostnames from DB to Redis, which is
     * how a stale Redis can be repaired.
     */
    public Tenant retryProvisioning(UUID id, String actor) {
        Tenant t = get(id);
        if (t.getStatus() == TenantStatus.ACTIVE) {
            publishRoutes(t);
            return t;  // no-op; not auditable
        }
        if (t.getStatus() != TenantStatus.FAILED) {
            var ex = new IllegalStateException(
                "Cannot retry provisioning for tenant in status " + t.getStatus());
            audit.recordFailure(SYSTEM_ACTOR, SYSTEM_KIND, t.getId(),
                "tenant.retry", "tenant", t.getId().toString(),
                null, ex,
                Map.of("currentStatus", t.getStatus().name()));
            throw ex;
        }

        Tenant after = provisionRealm(t);
        Map<String, Object> details = Map.of(
            "slug", after.getSlug(),
            "status", after.getStatus().name(),
            "realm", after.getRealmName() == null ? "" : after.getRealmName()
        );
        if (after.getStatus() == TenantStatus.ACTIVE) {
            audit.recordSuccess(SYSTEM_ACTOR, SYSTEM_KIND, after.getId(),
                "tenant.retry", "tenant", after.getId().toString(),
                null, details);
        } else {
            audit.recordFailure(SYSTEM_ACTOR, SYSTEM_KIND, after.getId(),
                "tenant.retry", "tenant", after.getId().toString(),
                null,
                new RuntimeException("Retry ended in status " + after.getStatus()),
                details);
        }
        return after;
    }

    @Transactional(readOnly = true)
    public Tenant get(UUID id) {
        return repo.findById(id)
            .filter(t -> !t.isDeleted())
            .orElseThrow(() -> new TenantNotFoundException(id.toString()));
    }

    @Transactional(readOnly = true)
    public Tenant getBySlug(String slug) {
        return repo.findBySlug(slug)
            .filter(t -> !t.isDeleted())
            .orElseThrow(() -> new TenantNotFoundException(slug));
    }

    @Transactional(readOnly = true)
    public List<Tenant> list() {
        return repo.findAllByDeletedAtIsNullOrderByCreatedAtDesc();
    }

    @Transactional(readOnly = true)
    public List<TenantHostname> hostnamesFor(UUID tenantId) {
        return hostnameRepo.findByTenantId(tenantId);
    }

    public void softDelete(UUID id, String actor) {
        Tenant t = get(id);
        var hostnames = hostnameRepo.findByTenantId(t.getId());
        routingTable.unpublishAll(hostnames);
        // Drop the route:<slug> cache so OpenResty stops serving the tenant
        // immediately. The DB row keeps routing_config for resurrect.
        routingConfig.deleteForTenant(t.getSlug());
        t.softDelete();
        audit.recordSuccess(SYSTEM_ACTOR, SYSTEM_KIND, t.getId(),
            "tenant.delete", "tenant", t.getId().toString(),
            null,
            Map.of("slug", t.getSlug(), "hostnameCount", hostnames.size()));
        // Hostname rows in DB are left in place (audit trail). They will not be
        // re-published unless the tenant is undeleted -- not implemented yet.
        // Realm disable in KC is also deferred.
    }

    private Map<String, Object> createPayload(
        String slug, String displayName,
        Map<String, Object> settings,
        List<HostnameAssignment> hostnames
    ) {
        var p = new java.util.LinkedHashMap<String, Object>();
        p.put("slug", slug);
        p.put("displayName", displayName);
        if (settings != null) p.put("settings", settings);
        if (hostnames != null) p.put("hostnames", hostnames);
        return p;
    }

    private String realmNameFor(String slug) {
        return "t-" + slug;
    }

    private Tenant provisionRealm(Tenant t) {
        String realmName = realmNameFor(t.getSlug());
        try {
            if (!keycloak.realmExists(realmName)) {
                keycloak.createRealm(realmName, t.getDisplayName());
            }
            t.markActive(realmName);
            publishRoutes(t);  // best-effort; failure does NOT mark tenant FAILED
        } catch (Exception e) {
            log.error("Realm provisioning failed for tenant {} (realm {})",
                      t.getSlug(), realmName, e);
            t.markFailed();
        }
        return repo.save(t);
    }

    private void publishRoutes(Tenant t) {
        try {
            var hostnames = hostnameRepo.findByTenantId(t.getId());
            routingTable.publishAll(hostnames, t.getSlug());
        } catch (Exception e) {
            log.error("Routing publish failed for tenant {}; recoverable via /retry",
                      t.getSlug(), e);
        }
    }
}
