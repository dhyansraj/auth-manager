package io.mcpmesh.auth.manager.keycloak;

import io.mcpmesh.auth.manager.service.UsermanagementBootstrap;
import org.keycloak.representations.idm.RealmRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Startup hook: iterates every realm and disables KC's lightweight access
 * tokens on the well-known system clients ({@code admin-cli},
 * {@code account}, {@code account-console}, {@code realm-management},
 * {@code security-admin-console}, {@code broker}) plus our own
 * {@code usermanagement} client.
 *
 * <p>Why this matters (deployment-gotchas memo #25): KC defaults
 * {@code client.use.lightweight.access.token.enabled=true} on system clients
 * in freshly-created realms. Lightweight tokens strip role claims from the
 * access token, which silently breaks role-based authz for any code path
 * that pulls roles out of the JWT instead of round-tripping to userinfo.
 * The trap is invisible at deploy time -- it only fires when an authz check
 * runs against a token that should have rolled but didn't.
 *
 * <p>This bootstrap runs after the other realm-touching bootstraps so any
 * realms / clients they materialise also get patched on the same boot.
 * Idempotent — already-disabled clients are silent no-ops. Best-effort —
 * per-realm and per-client failures are logged and skipped.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
public class SystemClientTokenBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(SystemClientTokenBootstrap.class);

    /**
     * KC's attribute key on a ClientRepresentation that toggles lightweight
     * access tokens. Stored as a string ("true" / "false") in the
     * attributes map regardless of its boolean semantics.
     */
    static final String LIGHTWEIGHT_TOKEN_ATTR =
        "client.use.lightweight.access.token.enabled";

    /**
     * The KC-installed system clients we patch in every realm, plus our own
     * {@code usermanagement} client. KC creates these automatically when a
     * realm is provisioned; the exact set is stable across recent KC majors.
     */
    static final List<String> SYSTEM_CLIENTS = List.of(
        UsermanagementBootstrap.CLIENT_SLUG,
        "admin-cli",
        "account",
        "account-console",
        "realm-management",
        "security-admin-console",
        "broker"
    );

    private final KeycloakAdminService keycloak;

    public SystemClientTokenBootstrap(KeycloakAdminService keycloak) {
        this.keycloak = keycloak;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            List<RealmRepresentation> realms = keycloak.listRealms();
            int touched = 0;
            for (RealmRepresentation r : realms) {
                String realmName = r.getRealm();
                if (realmName == null || realmName.isBlank()) continue;
                touched += disableLightweightTokensInRealm(realmName);
            }
            log.info("SystemClientTokenBootstrap: patched {} system clients across {} realms",
                touched, realms.size());
        } catch (Exception e) {
            log.warn("SystemClientTokenBootstrap: top-level failure ({}) — continuing", e.getMessage());
        }
    }

    /**
     * Sets {@code client.use.lightweight.access.token.enabled=false} on every
     * known system client present in {@code realmName}. Returns the number of
     * clients actually patched (skipped or missing clients don't count).
     */
    int disableLightweightTokensInRealm(String realmName) {
        int touched = 0;
        for (String clientId : SYSTEM_CLIENTS) {
            try {
                var uuidOpt = keycloak.findClientUuid(realmName, clientId);
                if (uuidOpt.isEmpty()) {
                    continue;
                }
                keycloak.setClientAttributes(
                    realmName, uuidOpt.get(),
                    Map.of(LIGHTWEIGHT_TOKEN_ATTR, "false"));
                touched++;
            } catch (Exception e) {
                log.warn("SystemClientTokenBootstrap: failed to patch client '{}' in realm '{}': {}",
                    clientId, realmName, e.getMessage());
            }
        }
        return touched;
    }
}
