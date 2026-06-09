package io.mcpmesh.auth.manager.email.templates;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Per-tenant rate-limit / quota knobs for the app-facing email send API.
 * Bound under {@code auth-manager.email.rate-limit.*}.
 *
 * <p>We send on tenants' authenticated domains through a shared SendGrid
 * account, so an app bug or abuse can burn a tenant's domain reputation and
 * our sender score. These two fixed windows (per-minute burst guard +
 * per-day quota) are best-effort reputation protection, not a hard security
 * gate (the limiter fails open if Redis is unreachable).
 *
 * <p>Defaults are platform-wide starting points.
 * TODO: per-tenant overrides (persisted on the tenant row) are a future
 * enhancement; until then every tenant shares these limits.
 */
@ConfigurationProperties("auth-manager.email.rate-limit")
public record EmailRateLimitProperties(
    Integer perMinute,
    Integer perDay,
    Boolean enabled
) {
    public EmailRateLimitProperties {
        if (perMinute == null || perMinute <= 0) perMinute = 100;
        if (perDay == null || perDay <= 0) perDay = 5000;
        if (enabled == null) enabled = Boolean.TRUE;
    }

    public boolean isEnabled() {
        return Boolean.TRUE.equals(enabled);
    }
}
