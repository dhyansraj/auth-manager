package io.mcpmesh.auth.manager.email.templates;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * An inline image asset belonging to a tenant email template, referenced from
 * the body via {@code {{asset:name}}} or {@code cid:name}. Mirrors
 * {@code auth_manager.email_template_assets} (V6). The (tenant_id, type_key)
 * pair is a composite FK back to {@link EmailTemplate}.
 */
@Entity
@Table(
    name = "email_template_assets",
    schema = "auth_manager",
    uniqueConstraints = @UniqueConstraint(columnNames = {"tenant_id", "type_key", "name"})
)
public class EmailTemplateAsset {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "type_key", nullable = false, length = 64)
    private String typeKey;

    @Column(name = "name", nullable = false, length = 128)
    private String name;

    @Column(name = "content_type", nullable = false, length = 128)
    private String contentType;

    @Column(name = "bytes", nullable = false)
    private byte[] bytes;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected EmailTemplateAsset() {
        // JPA
    }

    public EmailTemplateAsset(UUID tenantId, String typeKey, String name,
                              String contentType, byte[] bytes) {
        this.tenantId = tenantId;
        this.typeKey = typeKey;
        this.name = name;
        this.contentType = contentType;
        this.bytes = bytes;
    }

    public UUID getId() { return id; }
    public UUID getTenantId() { return tenantId; }
    public String getTypeKey() { return typeKey; }
    public String getName() { return name; }
    public String getContentType() { return contentType; }
    public byte[] getBytes() { return bytes; }
    public Instant getCreatedAt() { return createdAt; }
}
