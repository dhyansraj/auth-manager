package io.mcpmesh.auth.manager.service;

import io.mcpmesh.auth.manager.api.dto.AccessManifest;
import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.app.App;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.AppRepository;
import io.mcpmesh.auth.manager.service.exception.AppConflictException;
import io.mcpmesh.auth.manager.service.exception.AppNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

/**
 * Provisions the per-tenant "usermanagement" Keycloak client and applies the
 * default access manifest that powers tenant-admin self-serve user management.
 *
 * <p>Invoked by {@code TenantController} immediately after a tenant reaches
 * {@code ACTIVE}. Lives outside {@link TenantService} to avoid a circular
 * dependency with {@link AppService} (which already depends on TenantService).
 *
 * <p>Both steps are idempotent: re-running the bootstrap is a safe no-op.
 */
@Service
public class UsermanagementBootstrap {

    private static final Logger log = LoggerFactory.getLogger(UsermanagementBootstrap.class);

    public static final String CLIENT_SLUG = "usermanagement";
    public static final String DISPLAY_NAME = "User Management";
    public static final String ROLE_TENANT_ADMIN = "tenant-admin";
    public static final String ROLE_USER_VIEWER = "user-viewer";

    private static final ActorKind SYSTEM_KIND = ActorKind.SERVICE;

    private final AppService appService;
    private final ManifestService manifestService;
    private final AppRepository appRepo;
    private final AuditService audit;

    public UsermanagementBootstrap(AppService appService, ManifestService manifestService,
                                   AppRepository appRepo, AuditService audit) {
        this.appService = appService;
        this.manifestService = manifestService;
        this.appRepo = appRepo;
        this.audit = audit;
    }

    @Transactional
    public void bootstrap(Tenant tenant, String actor) {
        try {
            App app;
            try {
                var result = appService.create(tenant.getId(), CLIENT_SLUG, DISPLAY_NAME, actor);
                app = result.app();
            } catch (AppConflictException existing) {
                log.info("Bootstrap: usermanagement client already exists for tenant {}; skipping client create",
                         tenant.getSlug());
                app = appRepo.findByTenantIdAndSlug(tenant.getId(), CLIENT_SLUG)
                    .orElseThrow(() -> new AppNotFoundException(CLIENT_SLUG));
            }

            var applyResult = manifestService.apply(tenant.getId(), app.getId(), defaultManifest(), actor);
            if (applyResult.noOp()) {
                log.info("Bootstrap: default manifest already applied for tenant {} (no-op)",
                         tenant.getSlug());
            }

            audit.recordSuccess(actor, SYSTEM_KIND, tenant.getId(),
                "tenant.bootstrap", "tenant", tenant.getId().toString(),
                null,
                Map.of(
                    "tenantSlug", tenant.getSlug(),
                    "appSlug", CLIENT_SLUG,
                    "appId", app.getId().toString(),
                    "manifestNoOp", applyResult.noOp()));
        } catch (RuntimeException e) {
            audit.recordFailure(actor, SYSTEM_KIND, tenant.getId(),
                "tenant.bootstrap", "tenant", tenant.getId().toString(),
                null,
                e,
                Map.of("tenantSlug", tenant.getSlug(), "appSlug", CLIENT_SLUG));
            throw e;
        }
    }

    private static AccessManifest defaultManifest() {
        return new AccessManifest(
            List.of(ROLE_TENANT_ADMIN, ROLE_USER_VIEWER),
            List.of(
                new AccessManifest.ResourceSpec("user", List.of("view", "create", "update", "delete", "invite")),
                new AccessManifest.ResourceSpec("role", List.of("view", "assign", "revoke")),
                new AccessManifest.ResourceSpec("idp",  List.of("view", "create", "update", "delete"))
            ),
            Map.of(
                ROLE_TENANT_ADMIN, List.of(
                    new AccessManifest.RolePermission("user", List.of("view", "create", "update", "delete", "invite")),
                    new AccessManifest.RolePermission("role", List.of("view", "assign", "revoke")),
                    new AccessManifest.RolePermission("idp",  List.of("view", "create", "update", "delete"))
                ),
                ROLE_USER_VIEWER, List.of(
                    new AccessManifest.RolePermission("user", List.of("view")),
                    new AccessManifest.RolePermission("role", List.of("view"))
                )
            )
        );
    }
}
