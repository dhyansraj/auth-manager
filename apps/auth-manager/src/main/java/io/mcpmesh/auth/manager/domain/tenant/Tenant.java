package io.mcpmesh.auth.manager.domain.tenant;

import io.mcpmesh.auth.manager.routing.model.RoutingConfig;
import io.mcpmesh.auth.manager.theme.branding.BrandingConfig;
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
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Entity
@Table(name = "tenants")
public class Tenant {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String slug;

    @Column(name = "display_name", nullable = false)
    private String displayName;

    @Column(name = "realm_name")
    private String realmName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TenantStatus status;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> settings = new HashMap<>();

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "routing_config", nullable = false, columnDefinition = "jsonb")
    private RoutingConfig routingConfig;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "branding_config", columnDefinition = "jsonb")
    private BrandingConfig brandingConfig;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "created_by", nullable = false, updatable = false)
    private String createdBy;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "deleted_at")
    private Instant deletedAt;

    // -- Per-tenant email (V5). All optional; NULL falls back to platform
    // defaults (see SmtpConfigBootstrap#buildSmtpConfig).
    @Column(name = "email_from_address")
    private String emailFromAddress;

    @Column(name = "email_from_display_name")
    private String emailFromDisplayName;

    @Column(name = "email_reply_to_address")
    private String emailReplyToAddress;

    @Column(name = "sendgrid_domain_id")
    private Integer sendgridDomainId;

    @Column(name = "sendgrid_domain_valid")
    private Boolean sendgridDomainValid;

    protected Tenant() {
        // JPA
    }

    public Tenant(String slug, String displayName, String createdBy, Map<String, Object> settings) {
        this.slug = slug;
        this.displayName = displayName;
        this.createdBy = createdBy;
        this.status = TenantStatus.PENDING;
        if (settings != null) {
            this.settings = settings;
        }
    }

    // --- mutators (intentionally minimal; expand as use cases arrive) ---

    public void markActive(String realmName) {
        this.status = TenantStatus.ACTIVE;
        this.realmName = realmName;
    }

    public void markFailed() {
        this.status = TenantStatus.FAILED;
    }

    public void softDelete() {
        this.status = TenantStatus.DELETED;
        this.deletedAt = Instant.now();
    }

    /**
     * Clears the soft-delete and resets to PENDING for re-provisioning.
     * Caller is responsible for updating displayName/settings before save.
     */
    public void resurrect(String newDisplayName, Map<String, Object> newSettings) {
        this.deletedAt = null;
        this.status = TenantStatus.PENDING;
        this.realmName = null;  // re-provisioning will set this
        if (newDisplayName != null) this.displayName = newDisplayName;
        if (newSettings != null) this.settings = newSettings;
    }

    /**
     * Replaces the routing config wholesale. The mutator is intentionally
     * narrow: there is no per-rule add/remove; rules are managed as one
     * atomic blob via {@code RoutingConfigService.replaceForTenant}.
     */
    public void setRoutingConfig(RoutingConfig config) {
        if (config == null) throw new IllegalArgumentException("routingConfig is required");
        this.routingConfig = config;
    }

    /**
     * Replaces the rich-login branding config. {@code null} clears it back to
     * the "no customization" state — equivalent to deleting the column value.
     */
    public void setBrandingConfig(BrandingConfig config) {
        this.brandingConfig = config;
    }

    public boolean isDeleted() {
        return deletedAt != null;
    }

    // -- Email config mutators (V5) ------------------------------------------

    /**
     * Replaces the three per-tenant email override fields atomically. Any of
     * the three may be passed as null/blank to clear the override and fall
     * back to the platform / KC defaults.
     */
    public void setEmailOverrides(String fromAddress, String fromDisplayName, String replyTo) {
        this.emailFromAddress = blankToNull(fromAddress);
        this.emailFromDisplayName = blankToNull(fromDisplayName);
        this.emailReplyToAddress = blankToNull(replyTo);
    }

    /**
     * Records (or refreshes) the SendGrid domain-auth state for this tenant.
     * Either argument may be null when the domain hasn't been registered yet.
     */
    public void setSendgridDomain(Integer domainId, Boolean valid) {
        this.sendgridDomainId = domainId;
        this.sendgridDomainValid = valid;
    }

    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s.trim();
    }

    // -- Operator-disabled IdP aliases (persisted in settings JSONB) ---------

    /**
     * Returns the set of IdP aliases the tenant operator has explicitly
     * disabled. The bootstrap consults this set to avoid re-creating IdPs
     * that were intentionally removed via the admin UI.
     */
    @SuppressWarnings("unchecked")
    public Set<String> getDisabledIdps() {
        if (settings == null) return Set.of();
        Object node = settings.get("disabledIdps");
        if (!(node instanceof Collection<?> c)) return Set.of();
        return c.stream().map(Object::toString)
            .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * Adds or removes the given alias from the operator-disabled IdP set.
     * Mutates {@link #settings} in place; relies on JPA dirty-checking to
     * persist on commit.
     */
    public void setIdpDisabled(String alias, boolean disabled) {
        if (alias == null || alias.isBlank()) return;
        if (settings == null) settings = new LinkedHashMap<>();
        Set<String> current = new LinkedHashSet<>(getDisabledIdps());
        String key = alias.toLowerCase(Locale.ROOT);
        if (disabled) current.add(key);
        else current.remove(key);
        settings.put("disabledIdps", new ArrayList<>(current));
    }

    // --- getters (no setters; mutations go through the methods above) ---

    public UUID getId() { return id; }
    public String getSlug() { return slug; }
    public String getDisplayName() { return displayName; }
    public String getRealmName() { return realmName; }
    public TenantStatus getStatus() { return status; }
    public Map<String, Object> getSettings() { return settings; }
    public RoutingConfig getRoutingConfig() { return routingConfig; }
    public BrandingConfig getBrandingConfig() { return brandingConfig; }
    public Instant getCreatedAt() { return createdAt; }
    public String getCreatedBy() { return createdBy; }
    public Instant getUpdatedAt() { return updatedAt; }
    public Instant getDeletedAt() { return deletedAt; }
    public String getEmailFromAddress() { return emailFromAddress; }
    public String getEmailFromDisplayName() { return emailFromDisplayName; }
    public String getEmailReplyToAddress() { return emailReplyToAddress; }
    public Integer getSendgridDomainId() { return sendgridDomainId; }
    public Boolean getSendgridDomainValid() { return sendgridDomainValid; }
}
