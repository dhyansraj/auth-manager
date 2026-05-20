package io.mcpmesh.auth.manager.persistence;

import io.mcpmesh.auth.manager.domain.app.AppManifest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AppManifestRepository extends JpaRepository<AppManifest, UUID> {

    Optional<AppManifest> findByAppIdAndHash(UUID appId, String hash);

    @Query("SELECT COALESCE(MAX(m.version), 0) FROM AppManifest m WHERE m.appId = :appId")
    Integer maxVersionForApp(UUID appId);

    List<AppManifest> findByAppIdOrderByVersionDesc(UUID appId);
}
