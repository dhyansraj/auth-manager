package io.mcpmesh.auth.manager.email.templates;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * A per-tenant transactional email template (Mustache HTML body + optional
 * Mustache subject), keyed by a reserved {@code type_key} (e.g. "invitation").
 * Mirrors {@code auth_manager.email_templates} (V6). ddl-auto=validate, so this
 * mapping must match the migration exactly.
 */
@Entity
@Table(
    name = "email_templates",
    schema = "auth_manager",
    uniqueConstraints = @UniqueConstraint(columnNames = {"tenant_id", "type_key"})
)
public class EmailTemplate {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "type_key", nullable = false, length = 64)
    private String typeKey;

    @Column(name = "subject_template")
    private String subjectTemplate;

    @Column(name = "html_template", nullable = false)
    private String htmlTemplate;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected EmailTemplate() {
        // JPA
    }

    public EmailTemplate(UUID tenantId, String typeKey, String htmlTemplate, String subjectTemplate) {
        this.tenantId = tenantId;
        this.typeKey = typeKey;
        this.htmlTemplate = htmlTemplate;
        this.subjectTemplate = subjectTemplate;
    }

    public void update(String htmlTemplate, String subjectTemplate) {
        this.htmlTemplate = htmlTemplate;
        this.subjectTemplate = subjectTemplate;
    }

    public UUID getId() { return id; }
    public UUID getTenantId() { return tenantId; }
    public String getTypeKey() { return typeKey; }
    public String getSubjectTemplate() { return subjectTemplate; }
    public String getHtmlTemplate() { return htmlTemplate; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
