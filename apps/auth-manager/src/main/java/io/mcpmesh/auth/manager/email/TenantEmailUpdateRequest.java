package io.mcpmesh.auth.manager.email;

/**
 * Request body for PUT /api/v1/tenants/{tenantId}/email.
 *
 * <p>All three fields are optional / nullable:
 * <ul>
 *   <li>null / blank → clear the override + fall back to platform default.</li>
 *   <li>non-blank → apply as a per-tenant override.</li>
 * </ul>
 *
 * <p>{@code fromAddress} (if non-null) MUST be a valid email AND its domain
 * MUST match a SendGrid-authenticated domain registered on the tenant — see
 * {@link TenantEmailService#update}.
 */
public record TenantEmailUpdateRequest(
    String fromAddress,
    String fromDisplayName,
    String replyToAddress
) {}
