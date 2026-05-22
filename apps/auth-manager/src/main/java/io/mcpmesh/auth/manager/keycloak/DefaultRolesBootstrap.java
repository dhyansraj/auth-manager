package io.mcpmesh.auth.manager.keycloak;

import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.service.UsermanagementBootstrap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Startup backfill: iterates every active tenant realm and ensures the
 * {@code usermanagement:user-viewer} client role is a composite of the realm's
 * built-in {@code default-roles-<realm>} role.
 *
 * <p>This is the retroactive counterpart to the per-tenant baseline injection
 * in {@link UsermanagementBootstrap#bootstrap}: it fixes already-provisioned
 * tenants that were created before the baseline-injection logic landed (e.g.
 * acme + app1 in the existing beelink deployment).
 *
 * <p>Why this matters: KC's "First Broker Login" flow (for Google/GitHub
 * brokered users) bypasses our admin-API user-creation path, so any baseline
 * roles we inject in {@code UserManagementService.create} never reach brokered
 * users. KC auto-assigns {@code default-roles-<realm>} to every new user
 * regardless of how they were created, so wiring {@code user-viewer} into
 * that default role transparently grants it to everyone.
 *
 * <p>Idempotent — already-configured realms are silent no-ops.
 * Best-effort — per-realm failures are logged and skipped.
 */
@Component
public class DefaultRolesBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DefaultRolesBootstrap.class);

    /** Realm-name prefix used by tenant realms (see TenantService). */
    private static final String TENANT_REALM_PREFIX = "t-";

    private final KeycloakAdminService keycloak;
    private final TenantRepository tenantRepo;

    public DefaultRolesBootstrap(KeycloakAdminService keycloak, TenantRepository tenantRepo) {
        this.keycloak = keycloak;
        this.tenantRepo = tenantRepo;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            var tenants = tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc();
            for (var t : tenants) {
                String realmName = t.getRealmName();
                if (realmName == null || !realmName.startsWith(TENANT_REALM_PREFIX)) continue;
                try {
                    keycloak.ensureClientRoleInDefaultRoles(
                        realmName,
                        UsermanagementBootstrap.CLIENT_SLUG,
                        UsermanagementBootstrap.ROLE_USER_VIEWER);
                } catch (Exception e) {
                    log.warn("DefaultRolesBootstrap: backfill failed for realm '{}': {}",
                        realmName, e.getMessage());
                }
            }
        } catch (Exception e) {
            log.warn("DefaultRolesBootstrap: startup backfill aborted: {}", e.getMessage());
        }
    }
}
