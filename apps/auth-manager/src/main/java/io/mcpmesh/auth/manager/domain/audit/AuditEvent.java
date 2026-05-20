package io.mcpmesh.auth.manager.domain.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "audit_events")
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @CreationTimestamp
    @Column(name = "occurred_at", nullable = false, updatable = false)
    private Instant occurredAt;

    @Column(nullable = false)
    private String actor;

    @Enumerated(EnumType.STRING)
    @Column(name = "actor_kind", nullable = false)
    private ActorKind actorKind;

    @Column(name = "tenant_id")
    private UUID tenantId;

    @Column(nullable = false)
    private String action;

    @Column(name = "target_kind")
    private String targetKind;

    @Column(name = "target_id")
    private String targetId;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "request_hash", length = 64, columnDefinition = "char(64)")
    private String requestHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditResult result;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> details = new HashMap<>();

    protected AuditEvent() {
        // JPA
    }

    public AuditEvent(
        String actor, ActorKind actorKind,
        UUID tenantId, String action,
        String targetKind, String targetId,
        String requestHash, AuditResult result,
        Map<String, Object> details
    ) {
        this.actor = actor;
        this.actorKind = actorKind;
        this.tenantId = tenantId;
        this.action = action;
        this.targetKind = targetKind;
        this.targetId = targetId;
        this.requestHash = requestHash;
        this.result = result;
        if (details != null) this.details = details;
    }

    public Long getId() { return id; }
    public Instant getOccurredAt() { return occurredAt; }
    public String getActor() { return actor; }
    public ActorKind getActorKind() { return actorKind; }
    public UUID getTenantId() { return tenantId; }
    public String getAction() { return action; }
    public String getTargetKind() { return targetKind; }
    public String getTargetId() { return targetId; }
    public String getRequestHash() { return requestHash; }
    public AuditResult getResult() { return result; }
    public Map<String, Object> getDetails() { return details; }
}
