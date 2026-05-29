package io.mcpmesh.auth.manager.authflow;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * One-time per-tenant migration of the realm's {@code browserFlow} from
 * the built-in {@code browser} flow (shared across all KC realms) to our
 * cloned {@code mcpmesh-browser} flow.
 *
 * <p>Why: KC's built-in flows can't be edited in-place; mutating Username
 * Password Form requirement requires a private clone first. Doing the
 * clone-and-repoint at startup means subsequent {@code setPasswordEnabled}
 * calls find the flow already in place and just flip the requirement bit.
 *
 * <p>Non-destructive: cloning preserves all existing executions including
 * Username Password Form's {@code REQUIRED} requirement, so post-bootstrap
 * realms behave identically (login still works the same way). The toggle
 * UI is then available to flip it after.
 *
 * <p>Per-realm errors are caught + logged at WARN; one bad realm never
 * blocks the batch or fails startup.
 */
@Component
public class LoginMethodBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(LoginMethodBootstrap.class);

    /** Tenant realm-name prefix; matches {@code TenantService#realmNameFor}. */
    private static final String TENANT_REALM_PREFIX = "t-";

    private final LoginMethodService loginMethods;
    private final TenantRepository tenantRepo;

    public LoginMethodBootstrap(LoginMethodService loginMethods,
                                TenantRepository tenantRepo) {
        this.loginMethods = loginMethods;
        this.tenantRepo = tenantRepo;
    }

    @Override
    public void run(ApplicationArguments args) {
        int migrated = 0;
        int already = 0;
        int failed = 0;
        try {
            for (Tenant t : tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc()) {
                String realmName = t.getRealmName();
                if (realmName == null || !realmName.startsWith(TENANT_REALM_PREFIX)) continue;
                try {
                    boolean cloned = loginMethods.ensureClonedFlow(realmName);
                    if (cloned) {
                        log.info("LoginMethodBootstrap: tenant={} migrated to {}",
                            t.getSlug(), LoginMethodService.MCPMESH_BROWSER_FLOW);
                        migrated++;
                    } else {
                        log.debug("LoginMethodBootstrap: tenant={} already={}",
                            t.getSlug(), LoginMethodService.MCPMESH_BROWSER_FLOW);
                        already++;
                    }
                } catch (Exception e) {
                    log.warn("LoginMethodBootstrap: tenant={} migration failed: {}",
                        t.getSlug(), e.getMessage());
                    failed++;
                }
            }
        } catch (Exception e) {
            log.warn("LoginMethodBootstrap: startup pass aborted: {}", e.getMessage());
            return;
        }
        log.info("LoginMethodBootstrap: migrated={} already={} failed={}",
            migrated, already, failed);
    }
}
