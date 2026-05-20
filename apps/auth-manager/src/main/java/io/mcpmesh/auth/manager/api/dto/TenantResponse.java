package io.mcpmesh.auth.manager.api.dto;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.domain.tenant.TenantHostname;
import io.mcpmesh.auth.manager.domain.tenant.TenantStatus;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public record TenantResponse(
    UUID id,
    String slug,
    String displayName,
    String realmName,
    TenantStatus status,
    Map<String, Object> settings,
    List<HostnameAssignment> hostnames,
    Instant createdAt,
    String createdBy,
    Instant updatedAt
) {
    public static TenantResponse from(Tenant t, List<TenantHostname> hostnames) {
        return new TenantResponse(
            t.getId(),
            t.getSlug(),
            t.getDisplayName(),
            t.getRealmName(),
            t.getStatus(),
            t.getSettings(),
            hostnames.stream()
                .map(h -> new HostnameAssignment(h.getHostname(), h.getBackend()))
                .toList(),
            t.getCreatedAt(),
            t.getCreatedBy(),
            t.getUpdatedAt()
        );
    }
}
