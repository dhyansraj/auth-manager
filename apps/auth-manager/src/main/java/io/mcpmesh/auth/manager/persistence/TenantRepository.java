package io.mcpmesh.auth.manager.persistence;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface TenantRepository extends JpaRepository<Tenant, UUID> {

    Optional<Tenant> findBySlug(String slug);

    boolean existsBySlug(String slug);

    /** Active (non-soft-deleted) tenants. The DDL already has a partial index on this predicate. */
    List<Tenant> findAllByDeletedAtIsNullOrderByCreatedAtDesc();
}
