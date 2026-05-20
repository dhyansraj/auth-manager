package io.mcpmesh.auth.manager.service;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.service.exception.TenantConflictException;
import io.mcpmesh.auth.manager.service.exception.TenantNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Transactional
public class TenantService {

    private final TenantRepository repo;

    public TenantService(TenantRepository repo) {
        this.repo = repo;
    }

    public Tenant create(String slug, String displayName, Map<String, Object> settings, String actor) {
        if (repo.existsBySlug(slug)) {
            throw new TenantConflictException(slug);
        }
        Tenant t = new Tenant(slug, displayName, actor, settings);
        return repo.save(t);
        // Keycloak realm provisioning + Redis routing-table write get added in step 3b/3c.
    }

    @Transactional(readOnly = true)
    public Tenant get(UUID id) {
        return repo.findById(id)
            .filter(t -> !t.isDeleted())
            .orElseThrow(() -> new TenantNotFoundException(id.toString()));
    }

    @Transactional(readOnly = true)
    public Tenant getBySlug(String slug) {
        return repo.findBySlug(slug)
            .filter(t -> !t.isDeleted())
            .orElseThrow(() -> new TenantNotFoundException(slug));
    }

    @Transactional(readOnly = true)
    public List<Tenant> list() {
        return repo.findAllByDeletedAtIsNullOrderByCreatedAtDesc();
    }

    public void softDelete(UUID id, String actor) {
        Tenant t = get(id);
        t.softDelete();
        // Keycloak realm disable + Redis entry removal get added in step 3b/3c.
    }
}
