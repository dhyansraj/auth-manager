package io.mcpmesh.auth.manager.email.templates;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface EmailTemplateAssetRepository extends JpaRepository<EmailTemplateAsset, UUID> {

    List<EmailTemplateAsset> findByTenantIdAndTypeKeyOrderByNameAsc(UUID tenantId, String typeKey);

    Optional<EmailTemplateAsset> findByTenantIdAndTypeKeyAndName(UUID tenantId, String typeKey, String name);

    void deleteByTenantIdAndTypeKey(UUID tenantId, String typeKey);
}
