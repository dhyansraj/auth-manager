package io.mcpmesh.auth.manager.service;

import io.mcpmesh.auth.manager.api.dto.HostnameAssignment;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.domain.tenant.TenantHostname;
import io.mcpmesh.auth.manager.domain.tenant.TenantStatus;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.persistence.TenantHostnameRepository;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
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

    private final TenantRepository repo;
    private final TenantHostnameRepository hostnameRepo;
    private final KeycloakAdminService keycloak;
    private final RoutingTableService routingTable;

    public TenantService(
        TenantRepository repo,
        TenantHostnameRepository hostnameRepo,
        KeycloakAdminService keycloak,
        RoutingTableService routingTable
    ) {
        this.repo = repo;
        this.hostnameRepo = hostnameRepo;
        this.keycloak = keycloak;
        this.routingTable = routingTable;
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
        if (repo.existsBySlug(slug)) {
            throw new TenantConflictException(slug);
        }
        Tenant t = repo.save(new Tenant(slug, displayName, actor, settings));
        if (hostnames != null) {
            for (HostnameAssignment h : hostnames) {
                hostnameRepo.save(new TenantHostname(h.host(), t.getId(), h.backend()));
            }
        }
        return provisionRealm(t);
        // Audit row lands in step 3d.
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
            return t;
        }
        if (t.getStatus() != TenantStatus.FAILED) {
            throw new IllegalStateException(
                "Cannot retry provisioning for tenant in status " + t.getStatus());
        }
        return provisionRealm(t);
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
        t.softDelete();
        // Hostname rows in DB are left in place (audit trail). They will not be
        // re-published unless the tenant is undeleted -- not implemented yet.
        // Realm disable in KC is also deferred.
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
