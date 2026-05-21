package io.mcpmesh.auth.manager.service;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.app.App;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.persistence.AppRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

/**
 * Provisions the per-tenant "usermanagement" Keycloak client as a public UI
 * client with simple client roles. Powers tenant-admin self-serve user
 * management without dragging in Keycloak Authorization Services (overkill
 * for a single-audience UI client).
 *
 * <p>Invoked by {@code TenantController} immediately after a tenant reaches
 * {@code ACTIVE}. Lives outside {@link TenantService} to avoid a circular
 * dependency with {@link AppService} (which already depends on TenantService).
 *
 * <p>All steps are idempotent: re-running the bootstrap is a safe no-op.
 */
@Service
public class UsermanagementBootstrap {

    private static final Logger log = LoggerFactory.getLogger(UsermanagementBootstrap.class);

    public static final String CLIENT_SLUG = "usermanagement";
    public static final String DISPLAY_NAME = "User Management";
    public static final String ROLE_TENANT_ADMIN = "tenant-admin";
    public static final String ROLE_USER_VIEWER = "user-viewer";

    private static final ActorKind SYSTEM_KIND = ActorKind.SERVICE;
    private static final String SYSTEM_ACTOR = "system";

    private final AppService appService;
    private final AppRepository appRepo;
    private final AuditService audit;
    private final KeycloakAdminService keycloak;

    public UsermanagementBootstrap(AppService appService, AppRepository appRepo,
                                   AuditService audit, KeycloakAdminService keycloak) {
        this.appService = appService;
        this.appRepo = appRepo;
        this.audit = audit;
        this.keycloak = keycloak;
    }

    @Transactional
    public void bootstrap(Tenant tenant, String adminEmail, String actor) {
        Map<String, Object> details = Map.of("tenant_slug", tenant.getSlug(), "realm", tenant.getRealmName());
        try {
            // 1. Create the usermanagement App row + KC client (default confidential, recovered if exists)
            App app;
            if (appRepo.existsByTenantIdAndSlug(tenant.getId(), CLIENT_SLUG)) {
                app = appRepo.findByTenantIdAndSlug(tenant.getId(), CLIENT_SLUG)
                    .orElseThrow(() -> new IllegalStateException("App row vanished mid-bootstrap"));
                log.info("usermanagement app row already exists for tenant {}, ensuring KC state…", tenant.getSlug());
            } else {
                var result = appService.create(tenant.getId(), CLIENT_SLUG, DISPLAY_NAME, actor);
                app = result.app();
            }

            // Ensure KC client exists -- it might be missing if the realm was manually
            // recreated, or if a resurrect happened after KC realm was deleted by hand.
            if (keycloak.findClientUuid(tenant.getRealmName(), CLIENT_SLUG).isEmpty()) {
                log.info("KC usermanagement client missing for tenant {} — creating", tenant.getSlug());
                keycloak.createClient(tenant.getRealmName(), CLIENT_SLUG, DISPLAY_NAME);
            }

            // 2. Flip to public (UI client uses PKCE; no client_secret).
            keycloak.setClientPublic(tenant.getRealmName(), CLIENT_SLUG, true);

            // 3. Create client roles directly. Idempotent: keycloak.createClientRole skips if exists.
            keycloak.createClientRole(tenant.getRealmName(), findClientUuid(tenant), ROLE_TENANT_ADMIN);
            keycloak.createClientRole(tenant.getRealmName(), findClientUuid(tenant), ROLE_USER_VIEWER);

            audit.recordSuccess(actor, SYSTEM_KIND, tenant.getId(),
                "tenant.bootstrap", "tenant", tenant.getId().toString(),
                null, details);
        } catch (Exception e) {
            log.error("usermanagement bootstrap failed for tenant {}: {}", tenant.getSlug(), e.getMessage(), e);
            audit.recordFailure(actor, SYSTEM_KIND, tenant.getId(),
                "tenant.bootstrap", "tenant", tenant.getId().toString(),
                null, e, details);
            return;
        }

        if (adminEmail != null && !adminEmail.isBlank()) {
            bootstrapAdminUser(tenant, adminEmail, actor);
        }
    }

    private String findClientUuid(Tenant tenant) {
        return keycloak.findClientUuid(tenant.getRealmName(), CLIENT_SLUG)
            .orElseThrow(() -> new IllegalStateException("usermanagement client missing for " + tenant.getSlug()));
    }

    private void bootstrapAdminUser(Tenant tenant, String email, String actor) {
        try {
            String userId = keycloak.createUser(
                tenant.getRealmName(), email, email, "Admin", "User");
            keycloak.assignClientRoleToUser(
                tenant.getRealmName(), userId, CLIENT_SLUG, ROLE_TENANT_ADMIN);
            try {
                keycloak.sendExecuteActionsEmail(
                    tenant.getRealmName(), userId,
                    java.util.List.of("UPDATE_PASSWORD"),
                    86400);
            } catch (Exception emailErr) {
                // Email failure shouldn't block the bootstrap -- log + audit.
                log.warn("Failed to send invite email to {} (SMTP issue likely): {}",
                         email, emailErr.getMessage());
            }
            audit.recordSuccess(SYSTEM_ACTOR, SYSTEM_KIND, tenant.getId(),
                "tenant.bootstrap.admin", "user", userId,
                java.util.Map.of("email", email),
                java.util.Map.of("realm", tenant.getRealmName(),
                                  "role", ROLE_TENANT_ADMIN));
        } catch (Exception e) {
            log.error("Admin user bootstrap failed for {}: {}", email, e.getMessage(), e);
            audit.recordFailure(SYSTEM_ACTOR, SYSTEM_KIND, tenant.getId(),
                "tenant.bootstrap.admin", "user", null,
                java.util.Map.of("email", email),
                e,
                java.util.Map.of("realm", tenant.getRealmName()));
            // Don't rethrow -- the tenant itself is fine, admin bootstrap is recoverable
        }
    }
}
