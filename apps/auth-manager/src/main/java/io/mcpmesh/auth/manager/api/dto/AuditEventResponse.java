package io.mcpmesh.auth.manager.api.dto;

import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.audit.AuditEvent;
import io.mcpmesh.auth.manager.domain.audit.AuditResult;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record AuditEventResponse(
    Long id,
    Instant occurredAt,
    String actor,
    ActorKind actorKind,
    UUID tenantId,
    String action,
    String targetKind,
    String targetId,
    String requestHash,
    AuditResult result,
    Map<String, Object> details
) {
    public static AuditEventResponse from(AuditEvent e) {
        return new AuditEventResponse(
            e.getId(), e.getOccurredAt(), e.getActor(), e.getActorKind(),
            e.getTenantId(), e.getAction(), e.getTargetKind(), e.getTargetId(),
            e.getRequestHash(), e.getResult(), e.getDetails());
    }
}
