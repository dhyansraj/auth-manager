package io.mcpmesh.auth.manager.email;

/**
 * Request body for PUT /api/v1/tenants/{tenantId}/email/rate-limit.
 *
 * <p>Both fields are optional / nullable:
 * <ul>
 *   <li>null → clear the override + fall back to the platform default
 *       ({@code auth-manager.email.rate-limit.per-minute} / {@code .per-day}).</li>
 *   <li>non-null → apply as a per-tenant override; must be a positive int
 *       ≤ {@link TenantEmailService#RATE_LIMIT_MAX}.</li>
 * </ul>
 */
public record TenantEmailRateLimitUpdateRequest(
    Integer perMinute,
    Integer perDay
) {}
