package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.api.dto.AuditEventResponse;
import io.mcpmesh.auth.manager.api.dto.PageResponse;
import io.mcpmesh.auth.manager.domain.audit.AuditEvent;
import io.mcpmesh.auth.manager.persistence.AuditEventRepository;
import io.mcpmesh.auth.manager.security.TenantSecurity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/audit")
public class AuditController {

    private final AuditEventRepository repo;
    private final TenantSecurity tenantSecurity;

    public AuditController(AuditEventRepository repo, TenantSecurity tenantSecurity) {
        this.repo = repo;
        this.tenantSecurity = tenantSecurity;
    }

    /**
     * Global audit log, newest first. Platform-admins see every event;
     * tenant-scoped callers see only events scoped to their own tenant.
     * Unauthenticated requests get 403 via the {@code isAuthenticated()}
     * guard.
     *
     * <p>Default page size 50, max 200.
     */
    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public PageResponse<AuditEventResponse> list(
        @RequestParam(defaultValue = "0")  int page,
        @RequestParam(defaultValue = "50") int size
    ) {
        int safeSize = Math.min(Math.max(size, 1), 200);
        PageRequest pageRequest = PageRequest.of(page, safeSize);
        if (tenantSecurity.isPlatformAdmin()) {
            return PageResponse.from(
                repo.findAllByOrderByOccurredAtDesc(pageRequest),
                AuditEventResponse::from);
        }
        return tenantSecurity.currentTenantId()
            .map(id -> PageResponse.from(
                repo.findByTenantIdOrderByOccurredAtDesc(id, pageRequest),
                AuditEventResponse::from))
            .orElseGet(() -> PageResponse.from(
                Page.<AuditEvent>empty(pageRequest),
                AuditEventResponse::from));
    }
}
