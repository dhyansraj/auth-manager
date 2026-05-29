package io.mcpmesh.auth.lib;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Redis-backed {@link PermissionsCache} using Spring Data's
 * {@link StringRedisTemplate}. Shared across replicas; suitable for any
 * deployment that already runs Redis (typically the platform's sentinel
 * cluster).
 *
 * <p>This class is wired in by {@code RedisPermissionsCacheAutoConfiguration}
 * only when {@link StringRedisTemplate} is on the classpath — tenants who
 * don't add {@code spring-boot-starter-data-redis} to their pom never even
 * load this class, so the typed {@link StringRedisTemplate} field below
 * never triggers a {@code NoClassDefFoundError}.
 *
 * <p>Failures are swallowed by design: a Redis outage degrades to a cache
 * miss (read returns null, write is a no-op), the request continues, and a
 * rate-limited WARN is logged to avoid log spam.
 */
public class RedisPermissionsCache implements PermissionsCache {

    private static final Logger log = LoggerFactory.getLogger(RedisPermissionsCache.class);
    private static final String CACHE_DELIMITER = "\n";

    private final StringRedisTemplate redis;
    private volatile Instant lastWarnAt = Instant.EPOCH;

    public RedisPermissionsCache(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public Set<String> read(String key) {
        try {
            String joined = redis.opsForValue().get(key);
            return joined == null ? null : parseJoined(joined);
        } catch (Exception e) {
            warnRateLimited("read: redis unavailable, treating as cache miss", e);
            return null;
        }
    }

    @Override
    public void write(String key, Set<String> value, Duration ttl) {
        try {
            redis.opsForValue().set(key, String.join(CACHE_DELIMITER, value), ttl);
        } catch (Exception e) {
            warnRateLimited("write: redis unavailable, dropping cache write", e);
        }
    }

    private void warnRateLimited(String msg, Throwable t) {
        Instant now = Instant.now();
        if (now.isAfter(lastWarnAt.plus(Duration.ofMinutes(1)))) {
            log.warn("{} ({})", msg, t.getMessage());
            lastWarnAt = now;
        }
    }

    private static Set<String> parseJoined(String joined) {
        if (joined.isBlank()) return Set.of();
        Set<String> out = new LinkedHashSet<>();
        for (String s : joined.split(CACHE_DELIMITER)) {
            if (!s.isBlank()) out.add(s);
        }
        return Collections.unmodifiableSet(out);
    }
}
