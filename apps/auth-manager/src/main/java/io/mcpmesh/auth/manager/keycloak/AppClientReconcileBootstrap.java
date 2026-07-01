package io.mcpmesh.auth.manager.keycloak;

import io.mcpmesh.auth.manager.domain.app.App;
import io.mcpmesh.auth.manager.domain.tenant.TenantStatus;
import io.mcpmesh.auth.manager.persistence.AppRepository;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.service.AppService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Startup reconcile: recreates persisted app (Keycloak client) rows that are
 * missing from their tenant realm — the gap left behind when a realm is rebuilt.
 *
 * <p>Today only the {@code usermanagement} client is re-ensured on startup (via
 * {@link io.mcpmesh.auth.manager.service.UsermanagementBootstrap} +
 * {@link DefaultRolesBootstrap}). Arbitrary app clients created through the
 * app-create API — including NATIVE_PKCE native-app clients — are NOT, so a
 * realm rebuild silently loses them. This runner closes that gap.
 *
 * <p>For every ACTIVE tenant realm, each persisted {@link App} row is checked
 * against Keycloak:
 * <ul>
 *   <li>Client EXISTS → left completely untouched. This is deliberate: we only
 *       fill gaps, never re-shape a live client (usermanagement, backend, etc.).</li>
 *   <li>Client MISSING → recreated via {@link AppService#provisionClient}, which
 *       shares the exact create-time code path (create client + applyProfile for
 *       the stored profile + re-apply persisted audience mappers).</li>
 * </ul>
 *
 * <p>Idempotent, best-effort: per-tenant and per-app failures are logged and
 * skipped, never propagated. Ordered LOWEST_PRECEDENCE so it runs after the
 * realm / role bootstraps.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
public class AppClientReconcileBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AppClientReconcileBootstrap.class);

    /** Realm-name prefix used by tenant realms (see TenantService). */
    private static final String TENANT_REALM_PREFIX = "t-";

    private final KeycloakAdminService keycloak;
    private final TenantRepository tenantRepo;
    private final AppRepository appRepo;
    private final AppService appService;

    public AppClientReconcileBootstrap(KeycloakAdminService keycloak,
                                       TenantRepository tenantRepo,
                                       AppRepository appRepo,
                                       AppService appService) {
        this.keycloak = keycloak;
        this.tenantRepo = tenantRepo;
        this.appRepo = appRepo;
        this.appService = appService;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            var tenants = tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc();
            for (var t : tenants) {
                if (t.getStatus() != TenantStatus.ACTIVE) continue;
                String realmName = t.getRealmName();
                if (realmName == null || !realmName.startsWith(TENANT_REALM_PREFIX)) continue;

                List<App> apps;
                try {
                    apps = appRepo.findByTenantIdOrderByCreatedAtDesc(t.getId());
                } catch (Exception e) {
                    log.warn("AppClientReconcileBootstrap: failed to load apps for realm '{}': {}",
                        realmName, e.getMessage());
                    continue;
                }

                for (App app : apps) {
                    try {
                        // Create-if-missing ONLY: if the client already exists we do
                        // nothing — never re-shape a live client.
                        if (keycloak.findClientUuid(realmName, app.getClientId()).isPresent()) {
                            continue;
                        }
                        log.info("AppClientReconcileBootstrap: client '{}' missing in realm '{}' — "
                                + "recreating from persisted app row", app.getClientId(), realmName);
                        appService.provisionClient(t, app);
                    } catch (Exception e) {
                        log.warn("AppClientReconcileBootstrap: reconcile failed for app '{}' in realm '{}': {}",
                            app.getClientId(), realmName, e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            log.warn("AppClientReconcileBootstrap: startup reconcile aborted: {}", e.getMessage());
        }
    }
}
