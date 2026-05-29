package io.mcpmesh.auth.lib;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Activates the Redis-backed {@link PermissionsCache} when the tenant app
 * has pulled {@code spring-boot-starter-data-redis} (and therefore Spring's
 * own {@code RedisAutoConfiguration} has produced a {@link StringRedisTemplate}
 * bean) into their classpath.
 *
 * <p>{@code @ConditionalOnClass(StringRedisTemplate.class)} on the class
 * itself is what keeps this autoconfig from being loaded at all when the
 * dep is missing — Spring's autoconfig pipeline filters class-conditional
 * configs before resolving any of their method signatures, so the typed
 * parameter on {@link #redisPermissionsCache(StringRedisTemplate)} is safe.
 *
 * <p>{@code @AutoConfigureBefore(AuthLibAutoConfiguration.class)} ensures
 * this fires first; with {@code @ConditionalOnMissingBean(PermissionsCache.class)}
 * on the in-memory default, the Redis bean wins when both conditions hold.
 */
@AutoConfiguration
@ConditionalOnClass(StringRedisTemplate.class)
@AutoConfigureBefore(AuthLibAutoConfiguration.class)
public class RedisPermissionsCacheAutoConfiguration {

    @Bean
    @ConditionalOnBean(StringRedisTemplate.class)
    @ConditionalOnMissingBean(PermissionsCache.class)
    public PermissionsCache redisPermissionsCache(StringRedisTemplate redis) {
        return new RedisPermissionsCache(redis);
    }
}
