package io.mcpmesh.auth.manager.domain.app;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
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
@Table(name = "app_manifests")
public class AppManifest {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name = "app_id", nullable = false, updatable = false)
    private UUID appId;

    @Column(nullable = false, updatable = false)
    private Integer version;

    @Column(name = "manifest_yaml", nullable = false, columnDefinition = "text", updatable = false)
    private String manifestYaml;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "manifest_json", nullable = false, columnDefinition = "jsonb", updatable = false)
    private Map<String, Object> manifestJson = new HashMap<>();

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(nullable = false, length = 64, columnDefinition = "char(64)", updatable = false)
    private String hash;

    @CreationTimestamp
    @Column(name = "applied_at", nullable = false, updatable = false)
    private Instant appliedAt;

    @Column(name = "applied_by", nullable = false, updatable = false)
    private String appliedBy;

    protected AppManifest() { /* JPA */ }

    public AppManifest(UUID appId, Integer version, String manifestYaml,
                       Map<String, Object> manifestJson, String hash, String appliedBy) {
        this.appId = appId;
        this.version = version;
        this.manifestYaml = manifestYaml;
        if (manifestJson != null) this.manifestJson = manifestJson;
        this.hash = hash;
        this.appliedBy = appliedBy;
    }

    public UUID getId() { return id; }
    public UUID getAppId() { return appId; }
    public Integer getVersion() { return version; }
    public String getManifestYaml() { return manifestYaml; }
    public Map<String, Object> getManifestJson() { return manifestJson; }
    public String getHash() { return hash; }
    public Instant getAppliedAt() { return appliedAt; }
    public String getAppliedBy() { return appliedBy; }
}
