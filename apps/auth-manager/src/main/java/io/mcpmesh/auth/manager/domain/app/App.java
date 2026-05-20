package io.mcpmesh.auth.manager.domain.app;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "apps")
public class App {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false, updatable = false)
    private UUID tenantId;

    @Column(nullable = false, updatable = false)
    private String slug;

    @Column(name = "display_name", nullable = false)
    private String displayName;

    @Column(name = "client_id", nullable = false, updatable = false)
    private String clientId;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected App() { /* JPA */ }

    public App(UUID tenantId, String slug, String displayName, String clientId) {
        this.tenantId = tenantId;
        this.slug = slug;
        this.displayName = displayName;
        this.clientId = clientId;
    }

    public UUID getId() { return id; }
    public UUID getTenantId() { return tenantId; }
    public String getSlug() { return slug; }
    public String getDisplayName() { return displayName; }
    public String getClientId() { return clientId; }
    public Instant getCreatedAt() { return createdAt; }
}
