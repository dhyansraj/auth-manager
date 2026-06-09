package io.mcpmesh.auth.manager.email.templates;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface EmailTemplateRepository extends JpaRepository<EmailTemplate, UUID> {

    Optional<EmailTemplate> findByTenantIdAndTypeKey(UUID tenantId, String typeKey);

    List<EmailTemplate> findByTenantIdOrderByTypeKeyAsc(UUID tenantId);

    void deleteByTenantIdAndTypeKey(UUID tenantId, String typeKey);
}
