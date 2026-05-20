package io.mcpmesh.auth.manager.api.dto;

import io.mcpmesh.auth.manager.domain.app.App;

import java.time.Instant;
import java.util.UUID;

/**
 * App snapshot for callers. {@code clientSecret} is only populated on the
 * initial create response (returned by Keycloak once). Subsequent GETs
 * return null for that field; operators rotate via a dedicated endpoint
 * (not implemented yet).
 */
public record AppResponse(
    UUID id,
    UUID tenantId,
    String slug,
    String displayName,
    String clientId,
    String clientSecret,    // only on create; null otherwise
    Instant createdAt
) {
    public static AppResponse from(App a) {
        return new AppResponse(a.getId(), a.getTenantId(), a.getSlug(), a.getDisplayName(),
                               a.getClientId(), null, a.getCreatedAt());
    }

    public static AppResponse from(App a, String clientSecret) {
        return new AppResponse(a.getId(), a.getTenantId(), a.getSlug(), a.getDisplayName(),
                               a.getClientId(), clientSecret, a.getCreatedAt());
    }
}
