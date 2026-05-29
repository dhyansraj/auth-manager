package io.mcpmesh.auth.lib;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-process {@link PermissionsCache} backed by a {@link ConcurrentHashMap}
 * with lazy TTL eviction (entries are removed on read after expiry rather
 * than swept by a background thread). Sufficient for a single replica's
 * request bursts; not shared across replicas.
 *
 * <p>This is the default cache impl when {@code spring-boot-starter-data-redis}
 * is not on the classpath. Always available — depends only on JDK stdlib.
 */
public class InMemoryPermissionsCache implements PermissionsCache {

    private final ConcurrentMap<String, CacheEntry> store = new ConcurrentHashMap<>();

    @Override
    public Set<String> read(String key) {
        CacheEntry entry = store.get(key);
        if (entry == null) return null;
        if (entry.expiresAt.isBefore(Instant.now())) {
            store.remove(key, entry);
            return null;
        }
        return entry.value;
    }

    @Override
    public void write(String key, Set<String> value, Duration ttl) {
        store.put(key, new CacheEntry(value, Instant.now().plus(ttl)));
    }

    private record CacheEntry(Set<String> value, Instant expiresAt) {}
}
