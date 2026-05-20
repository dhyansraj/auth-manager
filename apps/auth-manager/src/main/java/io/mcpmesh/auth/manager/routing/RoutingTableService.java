package io.mcpmesh.auth.manager.routing;

import io.mcpmesh.auth.manager.domain.tenant.TenantHostname;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Map;

/**
 * Writes the tenant-routing entries that OpenResty's {@code route.lua}
 * reads on every request. Keys are {@code host:<hostname>}, values are
 * a HASH with at least a {@code backend} field; we also write
 * {@code tenant} for operator-side debugging via the
 * {@code dev-route-list} Makefile target.
 *
 * <p>Postgres is the source of truth; this Redis state is a derived
 * read cache. If Redis writes fail, the DB still has the record, and
 * {@code TenantService.retryProvisioning} republishes from DB.
 */
@Service
public class RoutingTableService {

    private static final Logger log = LoggerFactory.getLogger(RoutingTableService.class);

    private static final String KEY_PREFIX = "host:";
    private static final String FIELD_BACKEND = "backend";
    private static final String FIELD_TENANT  = "tenant";

    private final StringRedisTemplate redis;

    public RoutingTableService(StringRedisTemplate redis) {
        this.redis = redis;
    }

    /** Publish a single route. Overwrites any existing entry for the same hostname. */
    public void publish(String hostname, String backend, String tenantSlug) {
        String key = KEY_PREFIX + hostname;
        redis.opsForHash().putAll(key, Map.of(
            FIELD_BACKEND, backend,
            FIELD_TENANT,  tenantSlug
        ));
        log.info("Routing: published host={} -> backend={} (tenant={})",
                 hostname, backend, tenantSlug);
    }

    /** Publish all hostnames for a tenant in one go. */
    public void publishAll(Collection<TenantHostname> hostnames, String tenantSlug) {
        for (TenantHostname h : hostnames) {
            publish(h.getHostname(), h.getBackend(), tenantSlug);
        }
    }

    /** Remove a single route. Idempotent: no-op if the key doesn't exist. */
    public void unpublish(String hostname) {
        String key = KEY_PREFIX + hostname;
        Boolean removed = redis.delete(key);
        log.info("Routing: unpublished host={} (existed={})", hostname, removed);
    }

    /** Remove all routes for a collection of hostnames. */
    public void unpublishAll(Collection<TenantHostname> hostnames) {
        for (TenantHostname h : hostnames) {
            unpublish(h.getHostname());
        }
    }
}
