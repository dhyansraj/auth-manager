package io.mcpmesh.auth.manager.persistence;

import io.mcpmesh.auth.manager.domain.audit.AuditEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    /** Paged audit history for a specific tenant, newest first. */
    Page<AuditEvent> findByTenantIdOrderByOccurredAtDesc(UUID tenantId, Pageable pageable);

    /** Paged audit history across all tenants, newest first. */
    Page<AuditEvent> findAllByOrderByOccurredAtDesc(Pageable pageable);
}
