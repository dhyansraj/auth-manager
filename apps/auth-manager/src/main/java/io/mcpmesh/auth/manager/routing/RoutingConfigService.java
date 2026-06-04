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
        RoutingConfig sortedConfig = sortBySpecificity(newConfig);
        t.setRoutingConfig(sortedConfig);
        Tenant saved = tenants.save(t);

        // Audit BEFORE registering the after-commit sync so the audit row
        // is part of the same logical operation (AuditService uses
        // REQUIRES_NEW so it commits independently, which matches existing
        // behavior across the service layer).
        Map<String, Object> details = Map.of(
            "slug", slug,
            "ruleCount", sortedConfig.rules().size(),
            "targets", sortedConfig.targets()
        );
        audit.recordSuccess(SYSTEM_ACTOR, SYSTEM_KIND, saved.getId(),
            "routes.apply", "tenant", saved.getId().toString(),
            sortedConfig, details);

        registerRedisPublish(slug, sortedConfig);
        return saved.getRoutingConfig();
    }

    /**
     * Re-orders rules by path specificity so the router (first-match-wins)
     * always tries the most-specific rule first. Operators can add rules in
     * any order in the UI; we canonicalize at save time so a {@code /*}
     * catch-all placed first does not swallow more-specific rules like
     * {@code /ops/redis/*}.
     *
     * <p>Ordering (most-specific first):
     * <ol>
     *   <li>Exact paths (no trailing wildcard)</li>
     *   <li>Prefix-wildcard paths ({@code /foo/*}), longer prefix first</li>
     *   <li>The pure catch-all {@code /*} always last</li>
     * </ol>
     */
    static RoutingConfig sortBySpecificity(RoutingConfig incoming) {
        List<RoutingRule> sorted = incoming.rules().stream()
            .sorted(RoutingConfigService::compareSpecificity)
            .toList();
        return new RoutingConfig(sorted, normalizeTargets(incoming.targets()));
    }

    /**
     * Normalize every target value to a scheme-less {@code host[:port][/path]}
     * form so the edge ({@code router.lua}) can safely prepend {@code http://}
     * when proxying. An operator-supplied target with a scheme (e.g.
     * {@code http://192.168.10.50:3000}) would otherwise produce
     * {@code http://http://192.168.10.50:3000} and trip nginx's "invalid port
     * in upstream" 500. Keys are preserved; null/blank values pass through to
     * existing validation untouched.
     */
    static Map<String, String> normalizeTargets(Map<String, String> targets) {
        if (targets == null || targets.isEmpty()) {
            return targets;
        }
        return targets.entrySet().stream()
            .collect(java.util.stream.Collectors.toMap(
                Map.Entry::getKey,
                e -> normalizeTarget(e.getValue())
            ));
    }

    /**
     * Strip a leading {@code http://}/{@code https://} scheme (case-insensitive)
     * and any trailing {@code /} from a single target URL. Null/blank is
     * returned as-is so downstream validation still fires.
     */
    static String normalizeTarget(String url) {
        if (url == null) {
            return null;
        }
        String s = url.trim();
        if (s.isEmpty()) {
            return s;
        }
        if (s.regionMatches(true, 0, "http://", 0, 7)) {
            s = s.substring(7);
        } else if (s.regionMatches(true, 0, "https://", 0, 8)) {
            s = s.substring(8);
        }
        while (s.endsWith("/")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    static int compareSpecificity(RoutingRule a, RoutingRule b) {
        boolean aCatchAll = "/*".equals(a.path());
        boolean bCatchAll = "/*".equals(b.path());
        if (aCatchAll && !bCatchAll) return 1;   // a (catch-all) goes last
        if (!aCatchAll && bCatchAll) return -1;
        if (aCatchAll) return 0;                 // both catch-all

        boolean aWild = a.path().endsWith("/*");
        boolean bWild = b.path().endsWith("/*");
        // Exact matches outrank wildcards within the non-catch-all bucket.
        if (!aWild && bWild) return -1;
        if (aWild && !bWild) return 1;
        // Both wildcards or both exact: longer path wins (more specific).
        return Integer.compare(b.path().length(), a.path().length());
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

    /**
     * Redis-only publish: SET {@code route:<slug>} to the serialized config.
     * No DB write, no audit, no sort. Intended for boot-time republish
     * ({@code RoutingPublisherBootstrap}) and operator-driven repair where
     * DB is already authoritative and we just need to rebuild the Redis cache.
     */
    public void publishToRedis(String slug, RoutingConfig config) {
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
