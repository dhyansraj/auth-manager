package io.mcpmesh.auth.manager.service;

import io.mcpmesh.auth.manager.api.dto.HostnameAssignment;
import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.cloudflare.CloudflareTunnelService;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.domain.tenant.TenantHostname;
import io.mcpmesh.auth.manager.domain.tenant.TenantStatus;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.persistence.AppManifestRepository;
import io.mcpmesh.auth.manager.persistence.AppRepository;
import io.mcpmesh.auth.manager.persistence.TenantHostnameRepository;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.routing.RoutingConfigService;
import io.mcpmesh.auth.manager.routing.RoutingTableService;
import io.mcpmesh.auth.manager.service.exception.TenantConflictException;
import io.mcpmesh.auth.manager.service.exception.TenantNotFoundException;
import io.mcpmesh.auth.manager.theme.ThemeStorage;
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
    private final AppRepository appRepo;
    private final AppManifestRepository appManifestRepo;
    private final KeycloakAdminService keycloak;
    private final RoutingTableService routingTable;
    private final RoutingConfigService routingConfig;
    private final AuditService audit;
    private final CloudflareTunnelService cloudflare;
    private final ThemeStorage themeStorage;

    public TenantService(
        TenantRepository repo,
        TenantHostnameRepository hostnameRepo,
        AppRepository appRepo,
        AppManifestRepository appManifestRepo,
        KeycloakAdminService keycloak,
        RoutingTableService routingTable,
        RoutingConfigService routingConfig,
        AuditService audit,
        CloudflareTunnelService cloudflare,
        ThemeStorage themeStorage
    ) {
        this.repo = repo;
        this.hostnameRepo = hostnameRepo;
        this.appRepo = appRepo;
        this.appManifestRepo = appManifestRepo;
        this.keycloak = keycloak;
        this.routingTable = routingTable;
        this.routingConfig = routingConfig;
        this.audit = audit;
        this.cloudflare = cloudflare;
        this.themeStorage = themeStorage;
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
                // Capture the prior realm name BEFORE resurrect() nulls it on
                // the entity — soft-delete left the realm disabled (but intact)
                // in KC, so we re-enable it here. If the realm is genuinely
                // gone (force-delete history), provisionRealm() below will
                // recreate it from scratch.
                String priorRealmName = prior.getRealmName();
                prior.resurrect(displayName, settings);
                // Existing routingConfig is preserved across resurrection.
                t = repo.save(prior);
                // Clear any stale hostname rows from the prior life; replace with the new set
                hostnameRepo.deleteByTenantId(t.getId());
                if (priorRealmName != null && !priorRealmName.isBlank()) {
                    try {
                        keycloak.setRealmEnabled(priorRealmName, true);
                    } catch (Exception e) {
                        log.warn("Failed to re-enable KC realm '{}' during resurrect: {}",
                            priorRealmName, e.getMessage());
                    }
                }
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

        // Cloudflare provisioning: only for ACTIVE tenants. Best-effort —
        // CloudflareTunnelService swallows all CF errors. Hostnames live in DB
        // independently; CF state can be reconciled later (manual rerun, or
        // resurrection of the tenant).
        if (after.getStatus() == TenantStatus.ACTIVE && hostnames != null) {
            for (HostnameAssignment h : hostnames) {
                cloudflare.ensureHostname(h.host(), slug);
            }
        }
        return after;
    }

    /**
     * Force-marks a tenant FAILED. Called by the controller when post-create
     * bootstrap (UsermanagementBootstrap, IdP enablement, etc.) throws — the
     * realm exists but the tenant is incompletely provisioned. After this,
     * {@link #retryProvisioning} can recover it normally.
     *
     * No-op if the tenant is already FAILED. For tenants in any other state
     * (PENDING, SUSPENDED, DELETED, ACTIVE) the transition to FAILED is applied
     * + audited so operators can recover via /tenants/{id}/retry.
     */
    @Transactional
    public Tenant markFailed(UUID id, String reason, String actor) {
        Tenant t = get(id);
        if (t.getStatus() == TenantStatus.FAILED) {
            return t;
        }
        TenantStatus prevStatus = t.getStatus();
        t.markFailed();
        Tenant saved = repo.save(t);
        audit.recordFailure(actor, ActorKind.SERVICE, id,
            "tenant.bootstrap", "tenant", id.toString(),
            java.util.Map.of("previousStatus", prevStatus.name()),
            new RuntimeException("bootstrap_failed: " + reason),
            java.util.Map.of("realm", t.getRealmName(), "reason", reason));
        log.warn("Tenant {} marked FAILED (was {}): {}", id, prevStatus, reason);
        return saved;
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
        // Cloudflare cleanup: even though hostname rows persist for audit, the
        // public DNS + tunnel ingress should stop routing. Best-effort.
        for (var h : hostnames) {
            cloudflare.removeHostname(h.getHostname(), t.getSlug());
        }
        // Disable the KC realm so existing sessions are invalidated and new
        // logins fail with "Realm not enabled". User data + clients + theme are
        // preserved so resurrect() can flip the flag back on. Best-effort:
        // a KC failure must not block the DB soft-delete (we still want our
        // own state to reflect the operator's intent).
        if (t.getRealmName() != null && !t.getRealmName().isBlank()) {
            try {
                keycloak.setRealmEnabled(t.getRealmName(), false);
            } catch (Exception e) {
                log.warn("Failed to disable KC realm '{}' during soft delete: {}",
                    t.getRealmName(), e.getMessage());
            }
        }
        t.softDelete();
        audit.recordSuccess(SYSTEM_ACTOR, SYSTEM_KIND, t.getId(),
            "tenant.delete", "tenant", t.getId().toString(),
            null,
            Map.of("slug", t.getSlug(), "hostnameCount", hostnames.size()));
        // Hostname rows in DB are left in place (audit trail). They will not be
        // re-published unless the tenant is undeleted via create() (resurrect).
    }

    /**
     * Hard delete: runs the soft-delete cleanup (routes, CF, realm-disable) if
     * not already done, then permanently removes the KC realm, the theme
     * ConfigMap, and the tenant DB row (and child rows via JPA/DB cascade).
     * Irreversible — no resurrect is possible after this.
     *
     * <p>The DB row deletion relies on the {@code ON DELETE CASCADE} FKs on
     * {@code tenant_hostnames}, {@code apps} (which cascades to
     * {@code app_manifests}), and {@code user_cache}. We pre-delete app +
     * manifest rows via the JPA repositories so the persistence context is
     * consistent before {@code repo.deleteById} runs. Audit rows have no FK
     * (dropped in V2) and survive.
     */
    public void forceDelete(UUID id, String actor) {
        Tenant t = repo.findById(id)
            .orElseThrow(() -> new TenantNotFoundException(id.toString()));
        String realmName = t.getRealmName();
        String slug = t.getSlug();

        // Run the soft-delete cleanup first if the tenant isn't already
        // soft-deleted. We can't call softDelete(id, ...) directly here
        // because it goes through get(id) which filters out soft-deleted rows;
        // we already loaded the entity above so just inline the calls.
        if (!t.isDeleted()) {
            softDelete(id, actor);
        }

        // Permanently delete the KC realm. Idempotent on not-found.
        if (realmName != null && !realmName.isBlank()) {
            try {
                keycloak.deleteRealm(realmName);
            } catch (Exception e) {
                log.warn("Failed to delete KC realm '{}': {}", realmName, e.getMessage());
            }
        }

        // Delete the branding theme ConfigMap (if any). ThemeStorage already
        // takes the bare slug and applies the "theme-t-" prefix internally.
        try {
            themeStorage.deleteTheme(slug);
        } catch (Exception e) {
            log.warn("Failed to delete theme ConfigMap for slug '{}': {}", slug, e.getMessage());
        }

        // Pre-clear app_manifests via JPA (apps -> manifests cascade in DB,
        // but the JPA persistence context doesn't know about that, so we walk
        // the apps explicitly to keep Hibernate happy).
        var apps = appRepo.findByTenantIdOrderByCreatedAtDesc(id);
        for (var a : apps) {
            for (var m : appManifestRepo.findByAppIdOrderByVersionDesc(a.getId())) {
                appManifestRepo.delete(m);
            }
            appRepo.delete(a);
        }

        // tenant_hostnames + user_cache cascade in DB, but again clear via
        // JPA so the persistence context doesn't carry stale references.
        hostnameRepo.deleteByTenantId(id);

        repo.deleteById(id);

        audit.recordSuccess(SYSTEM_ACTOR, SYSTEM_KIND, id,
            "tenant.force_delete", "tenant", id.toString(),
            null,
            Map.of("slug", slug, "realmName", realmName == null ? "" : realmName));
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
                // CRITICAL: invalidate the admin token now that the new realm exists.
                // The previous token's role-mapping cache doesn't include realm-admin on
                // the new realm — first call from UsermanagementBootstrap returns 403
                // without this. Force the next admin REST call to re-authenticate.
                keycloak.invalidateAdminToken();
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
