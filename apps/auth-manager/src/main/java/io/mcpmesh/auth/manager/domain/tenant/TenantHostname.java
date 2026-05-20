package io.mcpmesh.auth.manager.domain.tenant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "tenant_hostnames")
public class TenantHostname {

    @Id
    @Column(nullable = false)
    private String hostname;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "backend_url", nullable = false)
    private String backend;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected TenantHostname() {
        // JPA
    }

    public TenantHostname(String hostname, UUID tenantId, String backend) {
        this.hostname = hostname;
        this.tenantId = tenantId;
        this.backend = backend;
    }

    public String getHostname() { return hostname; }
    public UUID getTenantId()   { return tenantId; }
    public String getBackend()  { return backend; }
    public Instant getCreatedAt() { return createdAt; }
}
