package io.mcpmesh.auth.manager.persistence;

import io.mcpmesh.auth.manager.domain.app.App;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AppRepository extends JpaRepository<App, UUID> {

    List<App> findByTenantIdOrderByCreatedAtDesc(UUID tenantId);

    Optional<App> findByTenantIdAndSlug(UUID tenantId, String slug);

    boolean existsByTenantIdAndSlug(UUID tenantId, String slug);
}
