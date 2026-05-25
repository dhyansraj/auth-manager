package io.mcpmesh.auth.manager.service;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.app.App;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.keycloak.KeycloakProperties;
import io.mcpmesh.auth.manager.persistence.AppRepository;
import io.mcpmesh.auth.manager.persistence.TenantHostnameRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
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
    public static final String ROLE_TENANT_USER_MANAGER = "tenant-user-manager";
    public static final String ROLE_USER_VIEWER = "user-viewer";

    private static final ActorKind SYSTEM_KIND = ActorKind.SERVICE;
    private static final String SYSTEM_ACTOR = "system";

    private final AppService appService;
    private final AppRepository appRepo;
    private final AuditService audit;
    private final KeycloakAdminService keycloak;
    private final TenantHostnameRepository hostnameRepo;
    private final KeycloakProperties kcProps;

    public UsermanagementBootstrap(AppService appService, AppRepository appRepo,
                                   AuditService audit, KeycloakAdminService keycloak,
                                   TenantHostnameRepository hostnameRepo,
                                   KeycloakProperties kcProps) {
        this.appService = appService;
        this.appRepo = appRepo;
        this.audit = audit;
        this.keycloak = keycloak;
        this.hostnameRepo = hostnameRepo;
        this.kcProps = kcProps;
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
            String clientUuid = findClientUuid(tenant);
            keycloak.createClientRole(tenant.getRealmName(), clientUuid, ROLE_TENANT_ADMIN);
            keycloak.createClientRole(tenant.getRealmName(), clientUuid, ROLE_TENANT_USER_MANAGER);
            keycloak.createClientRole(tenant.getRealmName(), clientUuid, ROLE_USER_VIEWER);

            // 4. Make user-viewer a composite of the realm's default-roles-<realm>
            //    so every new user (including brokered Google/GitHub users via
            //    KC's First Broker Login flow) lands with read-only access to
            //    the usermanagement UI. Idempotent.
            keycloak.ensureClientRoleInDefaultRoles(
                tenant.getRealmName(), CLIENT_SLUG, ROLE_USER_VIEWER);

            // 5. Materialize the atomic permission catalog (Phase A of the
            //    admin-ui permission migration). Each atomic perm becomes a
            //    flat client role on the usermanagement client; the existing
            //    composite roles (tenant-admin / tenant-user-manager) become
            //    composites that include the appropriate atomic perms so
            //    KC flattens them into the JWT's resource_access claim.
            //    Idempotent: all create + wire calls skip when already present.
            ensureAtomicPermsAndComposites(tenant.getRealmName(), clientUuid);

            // 6. Declare the canonical redirect URIs + web origins for the
            //    usermanagement client. Replaces any drift introduced by
            //    ad-hoc kcadm scripts. Idempotent.
            ensureStandardRedirectUris(tenant, clientUuid);

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

    /**
     * Creates each tenant-level atomic permission as a client role on
     * {@code usermanagement} and wires the existing composite roles
     * ({@code tenant-admin}, {@code tenant-user-manager}) to include the
     * appropriate atomic permissions as composites. Package-private so the
     * startup backfill ({@code DefaultRolesBootstrap}) can re-use the same
     * code path on already-provisioned realms.
     *
     * <p>All steps are idempotent: re-running is a safe no-op.
     */
    void ensureAtomicPermsAndComposites(String realmName, String clientUuid) {
        // Create each atomic perm as a flat client role.
        for (String perm : PlatformPermissions.TENANT_ADMIN_BUNDLE) {
            keycloak.createClientRole(realmName, clientUuid, perm);
        }
        // Wire composite memberships.
        keycloak.ensureClientRoleComposites(
            realmName, clientUuid, ROLE_TENANT_ADMIN,
            PlatformPermissions.TENANT_ADMIN_BUNDLE);
        keycloak.ensureClientRoleComposites(
            realmName, clientUuid, ROLE_TENANT_USER_MANAGER,
            PlatformPermissions.TENANT_USER_MANAGER_BUNDLE);
    }

    /**
     * Resets the {@code usermanagement} client's {@code redirectUris} +
     * {@code webOrigins} to the canonical set derived from the tenant's
     * hostnames plus the platform host. Public so the startup backfill
     * ({@code DefaultRolesBootstrap}, in a different package) can re-use the
     * same code path on already-provisioned realms.
     *
     * <p>Idempotent: same tenant + same KC properties always produces the
     * same KC state, intentionally so re-runs heal drift.
     */
    public void ensureStandardRedirectUris(Tenant tenant, String clientUuid) {
        List<String> hostnames = hostnameRepo.findByTenantId(tenant.getId()).stream()
            .map(h -> h.getHostname())
            .toList();
        String platformHost = kcProps.platform() == null ? null : kcProps.platform().host();
        keycloak.setStandardRedirectUris(
            tenant.getRealmName(), clientUuid, hostnames, platformHost, false);
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
