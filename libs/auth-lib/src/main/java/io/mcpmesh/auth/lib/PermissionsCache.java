package io.mcpmesh.auth.lib;

import java.time.Duration;
import java.util.Set;

/**
 * Pluggable cache for UMA permission lookup results. Two implementations:
 * {@link InMemoryPermissionsCache} (always available, default) and
 * {@code RedisPermissionsCache} (active when {@code StringRedisTemplate} is
 * on the classpath, opt-in by adding {@code spring-boot-starter-data-redis}
 * to the tenant app's pom).
 *
 * <p>The split lets the lib stay decoupled from Spring Data Redis at the
 * classpath level — the Redis impl is in its own class, loaded only when
 * the type is resolvable. Prior to 0.3.1 a typed {@code StringRedisTemplate}
 * parameter on {@code Permissions}' ctor forced the JVM to resolve the
 * Redis class at class-load time, breaking tenants who didn't pull the
 * starter into their own pom even when they only wanted the in-memory mode.
 */
public interface PermissionsCache {

    /** Returns the cached permission set for the key, or null on miss / error. */
    Set<String> read(String key);

    /** Best-effort write. Failures must be swallowed (cache is advisory). */
    void write(String key, Set<String> value, Duration ttl);
}
