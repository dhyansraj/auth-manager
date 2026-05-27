package io.mcpmesh.auth.manager.routing;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.domain.tenant.TenantHostname;
import io.mcpmesh.auth.manager.domain.tenant.TenantStatus;
import io.mcpmesh.auth.manager.persistence.TenantHostnameRepository;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.routing.model.RoutingConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Startup hook: re-publishes every ACTIVE tenant's routing entries
 * ({@code host:<hostname>} hashes + {@code route:<slug>} keys) from
 * Postgres (source of truth) into Redis (read cache).
 *
 * <p>Why: Redis is ephemeral in the platform's recovery model — a Redis
 * restart drops every route entry and every tenant goes dark at the
 * edge router until something repaints the cache. Without this hook
 * the only recovery is manual re-PUT of every tenant's routing config.
 * With this hook, restarting the auth-manager pod is sufficient to
 * fully reconcile Redis from DB.
 *
 * <p>Idempotent — HSET / SET semantics make re-publishing the same
 * values a no-op against a warm Redis. Per-tenant try/catch so one
 * bad tenant doesn't block the rest; this hook never fails startup
 * (Redis being briefly unavailable should not keep the platform from
 * coming up).
 *
 * <p>Runs at {@code LOWEST_PRECEDENCE - 10} so it fires BEFORE
 * {@link io.mcpmesh.auth.manager.keycloak.SystemClientTokenBootstrap}
 * ({@code LOWEST_PRECEDENCE}) — routes should be back in Redis as
 * early as possible in the boot sequence.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE - 10)
public class RoutingPublisherBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(RoutingPublisherBootstrap.class);

    private final TenantRepository tenantRepo;
    private final TenantHostnameRepository hostnameRepo;
    private final RoutingTableService routingTable;
    private final RoutingConfigService routingConfig;

    public RoutingPublisherBootstrap(TenantRepository tenantRepo,
                                     TenantHostnameRepository hostnameRepo,
                                     RoutingTableService routingTable,
                                     RoutingConfigService routingConfig) {
        this.tenantRepo = tenantRepo;
        this.hostnameRepo = hostnameRepo;
        this.routingTable = routingTable;
        this.routingConfig = routingConfig;
    }

    @Override
    public void run(ApplicationArguments args) {
        republishAll();
    }

    /**
     * Iterates ACTIVE tenants and republishes their {@code host:*} and
     * {@code route:*} entries from DB to Redis. Returns a small report
     * the admin repair endpoint can serialize back to the operator.
     * Never throws — per-tenant failures are counted and logged.
     */
    public RepublishReport republishAll() {
        int hostsPublished = 0;
        int routesPublished = 0;
        int failures = 0;
        int tenantsScanned = 0;

        List<Tenant> tenants;
        try {
            tenants = tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc();
        } catch (Exception e) {
            log.warn("RoutingPublisherBootstrap: failed to load tenants ({}) — skipping republish",
                e.getMessage());
            return new RepublishReport(0, 0, 0, 1);
        }

        for (Tenant t : tenants) {
            if (t.getStatus() != TenantStatus.ACTIVE) continue;
            tenantsScanned++;
            try {
                List<TenantHostname> hosts = hostnameRepo.findByTenantId(t.getId());
                routingTable.publishAll(hosts, t.getSlug());
                hostsPublished += hosts.size();

                RoutingConfig cfg = t.getRoutingConfig();
                if (cfg != null && !cfg.rules().isEmpty()) {
                    routingConfig.publishToRedis(t.getSlug(), cfg);
                    routesPublished++;
                }
            } catch (Exception e) {
                log.warn("RoutingPublisherBootstrap: failed to republish tenant {}: {}",
                    t.getSlug(), e.getMessage());
                failures++;
            }
        }

        log.info("RoutingPublisherBootstrap: republished {} hosts + {} routes across {} active tenants ({} failures)",
            hostsPublished, routesPublished, tenantsScanned, failures);
        return new RepublishReport(tenantsScanned, hostsPublished, routesPublished, failures);
    }

    /** Result counts for a republish pass. */
    public record RepublishReport(int tenantsScanned, int hostsPublished, int routesPublished, int failures) {}
}
