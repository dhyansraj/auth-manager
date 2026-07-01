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

    @Column(name = "profile")
    private String profile;

    @Column(name = "ios_team_id")
    private String iosTeamId;

    @Column(name = "ios_bundle_id")
    private String iosBundleId;

    @Column(name = "android_package")
    private String androidPackage;

    @Column(name = "android_cert_sha256")
    private String androidCertSha256;

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

    public String getProfile() { return profile; }
    public void setProfile(String profile) { this.profile = profile; }

    public String getIosTeamId() { return iosTeamId; }
    public void setIosTeamId(String iosTeamId) { this.iosTeamId = iosTeamId; }

    public String getIosBundleId() { return iosBundleId; }
    public void setIosBundleId(String iosBundleId) { this.iosBundleId = iosBundleId; }

    public String getAndroidPackage() { return androidPackage; }
    public void setAndroidPackage(String androidPackage) { this.androidPackage = androidPackage; }

    public String getAndroidCertSha256() { return androidCertSha256; }
    public void setAndroidCertSha256(String androidCertSha256) { this.androidCertSha256 = androidCertSha256; }
}
