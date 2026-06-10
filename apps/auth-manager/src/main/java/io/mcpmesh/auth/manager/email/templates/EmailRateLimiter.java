package io.mcpmesh.auth.manager.email.templates;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Per-tenant fixed-window rate limiter / quota for the app-facing email send
 * API, backed by Redis counters so the limit holds across auth-manager's
 * replicas (in-memory state would only guard a single pod).
 *
 * <p>Two windows are enforced per tenant on each send:
 * <ul>
 *   <li><b>Per-minute burst</b> — key {@code email:rl:m:{tenantId}:{epochMinute}},
 *       {@code INCR} with a 70s TTL set on the first hit. Catches a runaway
 *       loop hammering the API.</li>
 *   <li><b>Per-day quota</b> — key {@code email:rl:d:{tenantId}:{epochDay}},
 *       {@code INCR} with a ~25h TTL. Caps total daily volume on the tenant's
 *       sending domain.</li>
 * </ul>
 *
 * <p>The per-minute window is checked (and incremented) first; if it rejects
 * we never touch the day counter, so a throttled burst does not also burn the
 * daily quota. When a window is exceeded the increment that crossed the line
 * still happened (we accept a 1-count over-count rather than pay for a
 * decrement) but no email is sent.
 *
 * <p><b>Fail-open:</b> any error talking to Redis is logged at WARN and the
 * send is ALLOWED. The limit is best-effort reputation protection, not a hard
 * security gate, and breaking email delivery because the limiter hiccuped would
 * be worse than briefly losing the cap.
 */
@Component
public class EmailRateLimiter {

    private static final Logger log = LoggerFactory.getLogger(EmailRateLimiter.class);

    private static final String MIN_PREFIX = "email:rl:m:";
    private static final String DAY_PREFIX = "email:rl:d:";

    // 70s gives a small grace past the 60s window so a counter is never
    // resurrected by a late increment after its window has rolled.
    private static final Duration MIN_TTL = Duration.ofSeconds(70);
    // ~25h: comfortably outlives the 24h window so the day boundary, not the
    // TTL, is what resets the quota.
    private static final Duration DAY_TTL = Duration.ofSeconds(90_000);

    private final StringRedisTemplate redis;
    private final EmailRateLimitProperties props;

    public EmailRateLimiter(StringRedisTemplate redis, EmailRateLimitProperties props) {
        this.redis = redis;
        this.props = props;
    }

    /**
     * Count this send against the tenant's per-minute and per-day windows,
     * honoring the tenant's persisted rate-limit overrides
     * ({@code email_rl_per_minute} / {@code email_rl_per_day}) when set.
     *
     * @throws EmailRateLimitException if either window is now over its limit
     */
    public void checkAndIncrement(Tenant tenant) {
        checkAndIncrement(tenant.getId(), tenant.getEmailRlPerMinute(), tenant.getEmailRlPerDay());
    }

    /**
     * Count this send against the tenant's per-minute and per-day windows
     * using the platform-default limits (no per-tenant overrides).
     *
     * @throws EmailRateLimitException if either window is now over its limit
     */
    public void checkAndIncrement(UUID tenantId) {
        checkAndIncrement(tenantId, null, null);
    }

    /**
     * Count this send against the tenant's per-minute and per-day windows.
     * Effective limit per window = tenant override (when non-null and positive)
     * else the platform default from {@link EmailRateLimitProperties}.
     *
     * @throws EmailRateLimitException if either window is now over its limit
     */
    public void checkAndIncrement(UUID tenantId, Integer perMinuteOverride, Integer perDayOverride) {
        if (!props.isEnabled()) {
            return;
        }

        int perMinute = effectiveLimit(perMinuteOverride, props.perMinute());
        int perDay = effectiveLimit(perDayOverride, props.perDay());

        Instant now = Instant.now();
        long epochMinute = now.getEpochSecond() / 60;
        long epochDay = now.getEpochSecond() / 86_400;

        // Per-minute burst window first; on reject we skip the day counter so a
        // throttled burst doesn't also consume the daily quota.
        long minuteCount = incrementWindow(MIN_PREFIX + tenantId + ":" + epochMinute, MIN_TTL);
        if (minuteCount > perMinute) {
            long retryAfter = 60 - (now.getEpochSecond() % 60);
            throw new EmailRateLimitException(retryAfter,
                "Per-minute email limit exceeded for tenant " + tenantId
                    + " (" + perMinute + "/min)");
        }

        long dayCount = incrementWindow(DAY_PREFIX + tenantId + ":" + epochDay, DAY_TTL);
        if (dayCount > perDay) {
            long retryAfter = 86_400 - (now.getEpochSecond() % 86_400);
            throw new EmailRateLimitException(retryAfter,
                "Daily email quota exceeded for tenant " + tenantId
                    + " (" + perDay + "/day)");
        }
    }

    /** Tenant override (non-null, positive) wins; else the platform default. */
    private static int effectiveLimit(Integer override, int platformDefault) {
        return (override != null && override > 0) ? override : platformDefault;
    }

    /**
     * {@code INCR} the window key and set its TTL on the first hit. Returns the
     * post-increment count, or {@code 0} (fail-open sentinel, always under any
     * positive limit) if Redis is unreachable.
     */
    private long incrementWindow(String key, Duration ttl) {
        try {
            Long count = redis.opsForValue().increment(key);
            if (count == null) {
                // Unexpected null from the Redis client: treat as fail-open.
                log.warn("Email rate-limit: null INCR result for {} — allowing send", key);
                return 0;
            }
            if (count == 1L) {
                redis.expire(key, ttl);
            }
            return count;
        } catch (EmailRateLimitException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Email rate-limit: Redis unreachable for {} — failing open (allowing send): {}",
                key, e.getMessage());
            return 0;
        }
    }
}
