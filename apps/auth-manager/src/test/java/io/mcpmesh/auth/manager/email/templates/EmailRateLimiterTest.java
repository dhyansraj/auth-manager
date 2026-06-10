package io.mcpmesh.auth.manager.email.templates;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link EmailRateLimiter} driving a mocked
 * {@link StringRedisTemplate}: under-limit passes, crossing the per-minute or
 * per-day window throws {@link EmailRateLimitException}, and a Redis failure
 * fails open (send allowed).
 */
class EmailRateLimiterTest {

    private static final UUID TENANT = UUID.fromString("11111111-2222-3333-4444-555555555555");

    private StringRedisTemplate redis;
    private ValueOperations<String, String> ops;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        redis = mock(StringRedisTemplate.class);
        ops = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(ops);
    }

    private EmailRateLimiter limiter(int perMinute, int perDay, boolean enabled) {
        return new EmailRateLimiter(redis,
            new EmailRateLimitProperties(perMinute, perDay, enabled));
    }

    /** Make every INCR return a steadily climbing counter (shared across keys). */
    private void stubMonotonicIncrement() {
        AtomicLong counter = new AtomicLong();
        when(ops.increment(anyString())).thenAnswer(inv -> counter.incrementAndGet());
    }

    @Test
    void underLimit_passes_andSetsTtlOnFirstHit() {
        when(ops.increment(anyString())).thenReturn(1L);
        EmailRateLimiter rl = limiter(100, 5000, true);

        assertThatCode(() -> rl.checkAndIncrement(TENANT)).doesNotThrowAnyException();

        // First hit on both windows -> EXPIRE set on each.
        verify(redis, times(2)).expire(anyString(), any());
    }

    @Test
    void underLimit_doesNotSetTtl_afterFirstHit() {
        when(ops.increment(anyString())).thenReturn(5L);
        EmailRateLimiter rl = limiter(100, 5000, true);

        rl.checkAndIncrement(TENANT);

        verify(redis, never()).expire(anyString(), any());
    }

    @Test
    void crossingPerMinuteLimit_throws() {
        // minute counter returns 4 (> limit 3); day counter never touched.
        when(ops.increment(anyString())).thenReturn(4L);
        EmailRateLimiter rl = limiter(3, 5000, true);

        assertThatThrownBy(() -> rl.checkAndIncrement(TENANT))
            .isInstanceOf(EmailRateLimitException.class)
            .satisfies(e -> assertThat(((EmailRateLimitException) e).retryAfterSeconds())
                .isBetween(1L, 60L));

        // Per-minute rejected first: only the minute key was incremented.
        verify(ops, times(1)).increment(anyString());
    }

    @Test
    void crossingPerDayLimit_throws() {
        // minute key -> 1 (under), day key -> 2 (> day limit 1).
        when(ops.increment(anyString()))
            .thenReturn(1L)   // per-minute
            .thenReturn(2L);  // per-day
        EmailRateLimiter rl = limiter(100, 1, true);

        assertThatThrownBy(() -> rl.checkAndIncrement(TENANT))
            .isInstanceOf(EmailRateLimitException.class)
            .satisfies(e -> assertThat(((EmailRateLimitException) e).retryAfterSeconds())
                .isPositive());

        verify(ops, times(2)).increment(anyString());
    }

    @Test
    void redisFailure_failsOpen_allowsSend() {
        when(ops.increment(anyString()))
            .thenThrow(new org.springframework.dao.QueryTimeoutException("redis down"));
        EmailRateLimiter rl = limiter(1, 1, true);

        assertThatCode(() -> rl.checkAndIncrement(TENANT)).doesNotThrowAnyException();
    }

    @Test
    void nullIncrementResult_failsOpen() {
        when(ops.increment(anyString())).thenReturn(null);
        EmailRateLimiter rl = limiter(1, 1, true);

        assertThatCode(() -> rl.checkAndIncrement(TENANT)).doesNotThrowAnyException();
    }

    @Test
    void disabled_skipsRedisEntirely() {
        EmailRateLimiter rl = limiter(1, 1, false);

        rl.checkAndIncrement(TENANT);

        verify(redis, never()).opsForValue();
    }

    // -- per-tenant overrides --------------------------------------------------

    @Test
    void tenantPerMinuteOverride_winsOverPlatformDefault() {
        // Platform default 100/min; tenant override 3/min; counter at 4 → reject.
        when(ops.increment(anyString())).thenReturn(4L);
        EmailRateLimiter rl = limiter(100, 5000, true);

        assertThatThrownBy(() -> rl.checkAndIncrement(TENANT, 3, null))
            .isInstanceOf(EmailRateLimitException.class)
            .hasMessageContaining("(3/min)");
    }

    @Test
    void tenantOverride_canRaiseLimitAbovePlatformDefault() {
        // Platform default 3/min would reject at count 4; override 1000 allows.
        when(ops.increment(anyString())).thenReturn(4L);
        EmailRateLimiter rl = limiter(3, 3, true);

        assertThatCode(() -> rl.checkAndIncrement(TENANT, 1000, 1000))
            .doesNotThrowAnyException();
    }

    @Test
    void tenantPerDayOverride_winsOverPlatformDefault() {
        // minute -> 1 (under), day -> 2 (> tenant override 1, platform 5000).
        when(ops.increment(anyString()))
            .thenReturn(1L)   // per-minute
            .thenReturn(2L);  // per-day
        EmailRateLimiter rl = limiter(100, 5000, true);

        assertThatThrownBy(() -> rl.checkAndIncrement(TENANT, null, 1))
            .isInstanceOf(EmailRateLimitException.class)
            .hasMessageContaining("(1/day)");
    }

    @Test
    void nullOverrides_fallBackToPlatformDefaults() {
        // Same as crossingPerMinuteLimit_throws but via the override signature.
        when(ops.increment(anyString())).thenReturn(4L);
        EmailRateLimiter rl = limiter(3, 5000, true);

        assertThatThrownBy(() -> rl.checkAndIncrement(TENANT, null, null))
            .isInstanceOf(EmailRateLimitException.class)
            .hasMessageContaining("(3/min)");
    }

    @Test
    void nonPositiveOverride_ignored_fallsBackToPlatformDefault() {
        when(ops.increment(anyString())).thenReturn(4L);
        EmailRateLimiter rl = limiter(3, 5000, true);

        assertThatThrownBy(() -> rl.checkAndIncrement(TENANT, 0, null))
            .isInstanceOf(EmailRateLimitException.class)
            .hasMessageContaining("(3/min)");
    }

    @Test
    void tenantEntityOverload_resolvesOverridesFromColumns() {
        when(ops.increment(anyString())).thenReturn(4L);
        EmailRateLimiter rl = limiter(100, 5000, true);

        io.mcpmesh.auth.manager.domain.tenant.Tenant tenant =
            mock(io.mcpmesh.auth.manager.domain.tenant.Tenant.class);
        when(tenant.getId()).thenReturn(TENANT);
        when(tenant.getEmailRlPerMinute()).thenReturn(3);
        when(tenant.getEmailRlPerDay()).thenReturn(null);

        assertThatThrownBy(() -> rl.checkAndIncrement(tenant))
            .isInstanceOf(EmailRateLimitException.class)
            .hasMessageContaining("(3/min)");
    }

    @Test
    void repeatedSends_throwOnceLimitCrossed() {
        stubMonotonicIncrement();
        // perMinute is large so only the day counter is the binding limit; but
        // the shared monotonic counter increments on every key, so set both to
        // a value the cumulative count will exceed.
        EmailRateLimiter rl = limiter(1000, 3, true);

        // Calls 1..n increment two keys each; the day check trips once the
        // cumulative counter exceeds 3.
        assertThatThrownBy(() -> {
            for (int i = 0; i < 10; i++) {
                rl.checkAndIncrement(TENANT);
            }
        }).isInstanceOf(EmailRateLimitException.class);
    }
}
