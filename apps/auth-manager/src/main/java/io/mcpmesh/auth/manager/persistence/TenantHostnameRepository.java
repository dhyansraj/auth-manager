package io.mcpmesh.auth.manager.persistence;

import io.mcpmesh.auth.manager.domain.tenant.TenantHostname;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface TenantHostnameRepository extends JpaRepository<TenantHostname, String> {
    List<TenantHostname> findByTenantId(UUID tenantId);
    void deleteByTenantId(UUID tenantId);
}
