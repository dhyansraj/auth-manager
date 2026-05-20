package io.mcpmesh.auth.manager.api.dto;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.domain.tenant.TenantStatus;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record TenantResponse(
    UUID id,
    String slug,
    String displayName,
    String realmName,
    TenantStatus status,
    Map<String, Object> settings,
    Instant createdAt,
    String createdBy,
    Instant updatedAt
) {
    public static TenantResponse from(Tenant t) {
        return new TenantResponse(
            t.getId(),
            t.getSlug(),
            t.getDisplayName(),
            t.getRealmName(),
            t.getStatus(),
            t.getSettings(),
            t.getCreatedAt(),
            t.getCreatedBy(),
            t.getUpdatedAt()
        );
    }
}
