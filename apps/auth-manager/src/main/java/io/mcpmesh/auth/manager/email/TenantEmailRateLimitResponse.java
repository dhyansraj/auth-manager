package io.mcpmesh.auth.manager.email;

/**
 * Per-tenant email rate-limit view returned by {@link TenantEmailController}.
 *
 * <ul>
 *   <li>{@code perMinute} / {@code perDay} — resolved effective limits (tenant
 *       override if set, else the platform default). What the send-API limiter
 *       actually enforces.</li>
 *   <li>{@code perMinuteOverride} / {@code perDayOverride} — the raw tenant
 *       columns or null. Lets the UI distinguish "operator set this explicitly"
 *       from "falling back to platform default".</li>
 *   <li>{@code platformPerMinute} / {@code platformPerDay} — the platform
 *       defaults ({@code auth-manager.email.rate-limit.*}), so the UI can show
 *       what clearing an override falls back to.</li>
 *   <li>{@code enabled} — whether rate limiting is enabled platform-wide.</li>
 * </ul>
 */
public record TenantEmailRateLimitResponse(
    int perMinute,
    int perDay,
    Integer perMinuteOverride,
    Integer perDayOverride,
    int platformPerMinute,
    int platformPerDay,
    boolean enabled
) {}
