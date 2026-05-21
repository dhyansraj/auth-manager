package io.mcpmesh.auth.manager.routing;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.routing.model.AuthMode;
import io.mcpmesh.auth.manager.routing.model.RoutingConfig;
import io.mcpmesh.auth.manager.routing.model.RoutingRule;
import io.mcpmesh.auth.manager.service.exception.TenantNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.List;
import java.util.Map;

/**
 * Owns per-tenant routing rules: the Postgres source-of-truth ({@code tenants.routing_config}
 * JSONB) and the Redis read cache that OpenResty's {@code route.lua} consumes
 * ({@code route:<slug>} as a JSON string).
 *
 * <p>Postgres is authoritative. Redis is best-effort and re-published from
 * DB whenever {@code replaceForTenant} runs.
 */
@Service
public class RoutingConfigService {

    private static final Logger log = LoggerFactory.getLogger(RoutingConfigService.class);

    private static final String KEY_PREFIX = "route:";
    private static final String SYSTEM_ACTOR = "system";
    private static final ActorKind SYSTEM_KIND = ActorKind.SERVICE;

    private final TenantRepository tenants;
    private final StringRedisTemplate redis;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AuditService audit;

    public RoutingConfigService(
        TenantRepository tenants,
        StringRedisTemplate redis,
        AuditService audit
    ) {
        this.tenants = tenants;
        this.redis = redis;
        this.audit = audit;
    }

    /** Build the conventional defaults for a freshly-created tenant. */
    public RoutingConfig defaultFor(String slug) {
        String backendHost  = slug + "-backend.tenant-" + slug + ".svc.cluster.local:8080";
        String frontendHost = slug + "-ui.tenant-"      + slug + ".svc.cluster.local:80";
        return new RoutingConfig(
            List.of(
                new RoutingRule("/api/*", AuthMode.REQUIRED, "backend"),
                new RoutingRule("/*",     AuthMode.OPTIONAL, "frontend")
            ),
            Map.of(
                "backend",  backendHost,
                "frontend", frontendHost
            )
        );
    }

    @Transactional(readOnly = true)
    public RoutingConfig getForTenant(String slug) {
        Tenant t = tenants.findBySlug(slug)
            .filter(x -> !x.isDeleted())
            .orElseThrow(() -> new TenantNotFoundException(slug));
        return t.getRoutingConfig();
    }

    /**
     * Atomically replace the routing config for a tenant: writes the new
     * value to DB, registers a best-effort Redis publish that runs
     * {@code afterCommit}, and emits a {@code routes.apply} audit event.
     *
     * <p>The Redis write is post-commit (not in the transaction) so a
     * Redis outage does NOT roll back the DB row. The platform's recovery
     * model is "DB is truth, Redis is rebuilt from DB" -- if the Redis
     * publish fails the operator can re-PUT the same body to retry.
     */
    @Transactional
    public RoutingConfig replaceForTenant(String slug, RoutingConfig newConfig) {
        Tenant t = tenants.findBySlug(slug)
            .filter(x -> !x.isDeleted())
            .orElseThrow(() -> new TenantNotFoundException(slug));
        t.setRoutingConfig(newConfig);
        Tenant saved = tenants.save(t);

        // Audit BEFORE registering the after-commit sync so the audit row
        // is part of the same logical operation (AuditService uses
        // REQUIRES_NEW so it commits independently, which matches existing
        // behavior across the service layer).
        Map<String, Object> details = Map.of(
            "slug", slug,
            "ruleCount", newConfig.rules().size(),
            "targets", newConfig.targets()
        );
        audit.recordSuccess(SYSTEM_ACTOR, SYSTEM_KIND, saved.getId(),
            "routes.apply", "tenant", saved.getId().toString(),
            newConfig, details);

        registerRedisPublish(slug, newConfig);
        return saved.getRoutingConfig();
    }

    /**
     * Best-effort delete of the Redis cache key. Called from tenant
     * soft-delete; the DB row remains (audit trail) and routing_config
     * is preserved so a future undelete republishes from DB.
     */
    public void deleteForTenant(String slug) {
        String key = KEY_PREFIX + slug;
        try {
            Boolean removed = redis.delete(key);
            log.info("Routing: unpublished route:{} (existed={})", slug, removed);
        } catch (Exception e) {
            log.error("Routing: failed to unpublish route:{} (recoverable via republish)", slug, e);
        }
    }

    private void registerRedisPublish(String slug, RoutingConfig config) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    publishToRedis(slug, config);
                }
            });
        } else {
            // No active transaction (e.g. called outside @Transactional, like
            // from tests). Publish inline.
            publishToRedis(slug, config);
        }
    }

    private void publishToRedis(String slug, RoutingConfig config) {
        String key = KEY_PREFIX + slug;
        try {
            String json = objectMapper.writeValueAsString(config);
            redis.opsForValue().set(key, json);
            log.info("Routing: published {} ({} rules)", key, config.rules().size());
        } catch (JsonProcessingException e) {
            log.error("Routing: failed to serialize config for {} (DB has new value; Redis stale)",
                      slug, e);
        } catch (Exception e) {
            log.error("Routing: failed to publish {} (DB has new value; Redis stale)", key, e);
        }
    }
}
