package io.mcpmesh.auth.lib;

import io.mcpmesh.auth.lib.security.SecurityConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

/**
 * Core auto-config: security chain + a default in-memory {@link PermissionsCache}.
 *
 * <p>The Redis-backed cache lives in a separate
 * {@link RedisPermissionsCacheAutoConfiguration} class that is only loaded
 * when {@code StringRedisTemplate} is resolvable on the classpath. That
 * keeps the lib runnable in tenants who don't pull in
 * {@code spring-boot-starter-data-redis}.
 */
@AutoConfiguration
@EnableConfigurationProperties(AuthLibProperties.class)
@Import(SecurityConfig.class)
public class AuthLibAutoConfiguration {

    /**
     * Default in-memory cache, used unless a tenant defines their own
     * {@link PermissionsCache} bean (e.g. the Redis-backed one supplied by
     * {@link RedisPermissionsCacheAutoConfiguration} when Redis is on the
     * classpath).
     */
    @Bean
    @ConditionalOnMissingBean(PermissionsCache.class)
    public PermissionsCache inMemoryPermissionsCache() {
        return new InMemoryPermissionsCache();
    }
}
