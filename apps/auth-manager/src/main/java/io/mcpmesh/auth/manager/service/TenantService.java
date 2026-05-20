package io.mcpmesh.auth.manager.service;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.domain.tenant.TenantStatus;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.service.exception.TenantConflictException;
import io.mcpmesh.auth.manager.service.exception.TenantNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Transactional
public class TenantService {

    private static final Logger log = LoggerFactory.getLogger(TenantService.class);

    private final TenantRepository repo;
    private final KeycloakAdminService keycloak;

    public TenantService(TenantRepository repo, KeycloakAdminService keycloak) {
        this.repo = repo;
        this.keycloak = keycloak;
    }

    /**
     * Creates a tenant row and synchronously provisions its Keycloak realm.
     *
     * <p>The DB row is always saved (even if the KC call fails) so operators
     * have a record to retry against — see {@link #retryProvisioning(UUID, String)}.
     * On KC failure the tenant is persisted with status {@link TenantStatus#FAILED};
     * the HTTP layer still returns 201 because the tenant <em>resource</em> was
     * created. Callers must inspect {@code status} in the response to confirm
     * the realm is live.
     */
    public Tenant create(String slug, String displayName, Map<String, Object> settings, String actor) {
        if (repo.existsBySlug(slug)) {
            throw new TenantConflictException(slug);
        }
        Tenant t = repo.save(new Tenant(slug, displayName, actor, settings));
        return provisionRealm(t);
        // Redis routing-table write lands in step 3c.
        // Audit row lands in step 3d.
    }

    /**
     * Re-attempts realm provisioning for a tenant in {@link TenantStatus#FAILED}.
     * No-op (returns current state) for tenants already ACTIVE.
     * Throws if the tenant is in any other status (PENDING, SUSPENDED, DELETED).
     */
    public Tenant retryProvisioning(UUID id, String actor) {
        Tenant t = get(id);
        if (t.getStatus() == TenantStatus.ACTIVE) {
            return t;
        }
        if (t.getStatus() != TenantStatus.FAILED) {
            throw new IllegalStateException(
                "Cannot retry provisioning for tenant in status " + t.getStatus());
        }
        return provisionRealm(t);
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

    private String realmNameFor(String slug) {
        return "t-" + slug;
    }

    private Tenant provisionRealm(Tenant t) {
        String realmName = realmNameFor(t.getSlug());
        try {
            if (!keycloak.realmExists(realmName)) {
                keycloak.createRealm(realmName, t.getDisplayName());
            }
            t.markActive(realmName);
        } catch (Exception e) {
            log.error("Realm provisioning failed for tenant {} (realm {})",
                      t.getSlug(), realmName, e);
            t.markFailed();
        }
        return repo.save(t);
    }
}
