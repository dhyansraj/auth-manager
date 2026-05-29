package io.mcpmesh.auth.lib;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link RedisPermissionsCache} — only compiled+run when the
 * Redis starter is on the test classpath (the lib's pom carries
 * {@code spring-boot-starter-data-redis} as {@code <optional>true</optional>}
 * so test scope still resolves it).
 */
class RedisPermissionsCacheTest {

    @Test
    @SuppressWarnings("unchecked")
    void write_then_read_round_trips_via_redis_template() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        ValueOperations<String, String> ops = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(ops);

        RedisPermissionsCache cache = new RedisPermissionsCache(redis);

        Set<String> value = new LinkedHashSet<>();
        value.add("ORDER_VIEW");
        value.add("INVOICE_PAY");
        cache.write("perms:alice:123", value, Duration.ofSeconds(60));

        // Verify the joined payload is what gets sent to Redis.
        ArgumentCaptor<String> payload = ArgumentCaptor.forClass(String.class);
        verify(ops).set(eq("perms:alice:123"), payload.capture(), eq(Duration.ofSeconds(60)));
        assertThat(payload.getValue()).contains("ORDER_VIEW").contains("INVOICE_PAY");

        // Now stage a read returning the same joined payload and verify parse.
        when(ops.get("perms:alice:123")).thenReturn(payload.getValue());
        Set<String> roundTripped = cache.read("perms:alice:123");
        assertThat(roundTripped).containsExactlyInAnyOrder("ORDER_VIEW", "INVOICE_PAY");
    }

    @Test
    @SuppressWarnings("unchecked")
    void read_miss_returns_null() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        ValueOperations<String, String> ops = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(ops);
        when(ops.get(any(String.class))).thenReturn(null);

        RedisPermissionsCache cache = new RedisPermissionsCache(redis);
        assertThat(cache.read("perms:bob:456")).isNull();
    }

    @Test
    @SuppressWarnings("unchecked")
    void write_failure_is_swallowed() {
        // Redis down on write — must NOT propagate, since the cache is
        // advisory and the tenant request would otherwise fail.
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        ValueOperations<String, String> ops = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(ops);
        org.mockito.Mockito.doThrow(new RedisConnectionFailureException("simulated"))
            .when(ops).set(any(String.class), any(String.class), any(Duration.class));

        RedisPermissionsCache cache = new RedisPermissionsCache(redis);
        assertThatCode(() ->
            cache.write("perms:carol:789", Set.of("X"), Duration.ofSeconds(60))
        ).doesNotThrowAnyException();
    }

    @Test
    @SuppressWarnings("unchecked")
    void read_failure_returns_null_and_does_not_throw() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        ValueOperations<String, String> ops = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(ops);
        when(ops.get(any(String.class)))
            .thenThrow(new RedisConnectionFailureException("simulated"));

        RedisPermissionsCache cache = new RedisPermissionsCache(redis);
        assertThat(cache.read("perms:dave:000")).isNull();
    }
}
