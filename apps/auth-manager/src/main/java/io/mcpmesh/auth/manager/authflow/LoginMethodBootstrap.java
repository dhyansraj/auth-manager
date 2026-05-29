package io.mcpmesh.auth.manager.authflow;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Startup pass that REVERTS every active tenant realm's {@code browserFlow}
 * from our cloned {@code mcpmesh-browser} flow back to KC's built-in
 * {@code browser} flow.
 *
 * <p>Earlier versions of this bootstrap performed the opposite migration
 * (clone-and-repoint) to support flow-level password toggling. That approach
 * proved unworkable — see {@link LoginMethodService} for the full story — and
 * the password toggle is now a realm-attribute + theme-CSS feature. This
 * bootstrap therefore restores the default KC flow so login renders cleanly.
 *
 * <p>The orphaned {@code mcpmesh-browser} flow object is intentionally LEFT
 * IN PLACE on each realm. Deleting it is unnecessary (it's just an unused
 * flow definition) and avoids any "what if an in-flight auth session still
 * references it" hazard. Operators can clean it up manually later.
 *
 * <p>Per-realm errors are caught + logged at WARN; one bad realm never blocks
 * the batch or fails startup.
 */
@Component
public class LoginMethodBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(LoginMethodBootstrap.class);

    /** KC's built-in browser flow alias — what we want every realm to use. */
    public static final String BUILTIN_BROWSER_FLOW = "browser";

    /** Historical cloned-flow alias we are reverting AWAY from. */
    public static final String MCPMESH_BROWSER_FLOW = "mcpmesh-browser";

    /** Tenant realm-name prefix; matches {@code TenantService#realmNameFor}. */
    private static final String TENANT_REALM_PREFIX = "t-";

    private final TenantRepository tenantRepo;
    private final Keycloak kcAdmin;

    public LoginMethodBootstrap(TenantRepository tenantRepo, Keycloak kcAdmin) {
        this.tenantRepo = tenantRepo;
        this.kcAdmin = kcAdmin;
    }

    @Override
    public void run(ApplicationArguments args) {
        int reverted = 0;
        int already = 0;
        int failed = 0;
        try {
            for (Tenant t : tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc()) {
                String realmName = t.getRealmName();
                if (realmName == null || !realmName.startsWith(TENANT_REALM_PREFIX)) continue;
                try {
                    if (revertToBuiltinBrowser(realmName)) {
                        log.info("LoginMethodBootstrap: tenant={} reverted-to-builtin-browser",
                            t.getSlug());
                        reverted++;
                    } else {
                        log.debug("LoginMethodBootstrap: tenant={} already-on-builtin",
                            t.getSlug());
                        already++;
                    }
                } catch (Exception e) {
                    log.warn("LoginMethodBootstrap: tenant={} revert failed: {}",
                        t.getSlug(), e.getMessage());
                    failed++;
                }
            }
        } catch (Exception e) {
            log.warn("LoginMethodBootstrap: startup pass aborted: {}", e.getMessage());
            return;
        }
        log.info("LoginMethodBootstrap: reverted={} already-on-browser={} failed={}",
            reverted, already, failed);
    }

    /**
     * If the realm's {@code browserFlow} points at {@code mcpmesh-browser},
     * switch it back to {@code browser} and PUT the realm. Returns true when
     * a revert was issued; false when the realm is already on the built-in.
     */
    private boolean revertToBuiltinBrowser(String realmName) {
        RealmResource realm = kcAdmin.realm(realmName);
        RealmRepresentation rep = realm.toRepresentation();
        if (!MCPMESH_BROWSER_FLOW.equals(rep.getBrowserFlow())) {
            return false;
        }
        rep.setBrowserFlow(BUILTIN_BROWSER_FLOW);
        realm.update(rep);
        return true;
    }
}
