package io.mcpmesh.auth.manager.keycloak;

import io.mcpmesh.auth.manager.service.UsermanagementBootstrap;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

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
 * <p>On the same per-client patch pass, this bootstrap also backfills
 * {@code webOrigins=["+"]} on {@code account-console} and
 * {@code security-admin-console}. KC creates those SPA clients with an empty
 * {@code webOrigins}, which causes their session-poll iframe
 * ({@code login-status-iframe.html/init}) to 403 and spins the account UI
 * forever. {@code "+"} is KC's magic value meaning "use the redirect URIs as
 * allowed web origins", so we avoid hardcoding a hostname and stay correct
 * across dev / prod / future hostname changes.
 *
 * <p>This bootstrap runs after the other realm-touching bootstraps so any
 * realms / clients they materialise also get patched on the same boot.
 * Idempotent — already-disabled clients are silent no-ops, and clients whose
 * {@code webOrigins} list is already non-empty (operator customisation) are
 * left alone. Best-effort — per-realm and per-client failures are logged and
 * skipped.
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

    /**
     * Subset of {@link #SYSTEM_CLIENTS} that host browser SPAs needing
     * cross-origin iframe inits (session-status poll). Only these get the
     * {@code webOrigins=["+"]} backfill — the rest (admin-cli, account,
     * realm-management, broker, usermanagement) either aren't SPAs or already
     * have their webOrigins managed elsewhere.
     */
    static final Set<String> WEB_ORIGIN_CLIENTS = Set.of(
        "account-console",
        "security-admin-console"
    );

    private final KeycloakAdminService keycloak;

    public SystemClientTokenBootstrap(KeycloakAdminService keycloak) {
        this.keycloak = keycloak;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            List<RealmRepresentation> realms = keycloak.listRealms();
            int lightweightTouched = 0;
            int webOriginsTouched = 0;
            for (RealmRepresentation r : realms) {
                String realmName = r.getRealm();
                if (realmName == null || realmName.isBlank()) continue;
                int[] counts = patchSystemClientsInRealm(realmName);
                lightweightTouched += counts[0];
                webOriginsTouched += counts[1];
            }
            log.info("SystemClientTokenBootstrap: patched {} lightweight + {} webOrigins on system clients across {} realms",
                lightweightTouched, webOriginsTouched, realms.size());
        } catch (Exception e) {
            log.warn("SystemClientTokenBootstrap: top-level failure ({}) — continuing", e.getMessage());
        }
    }

    /**
     * Patches every known system client in {@code realmName} in a single
     * round-trip per client: disables lightweight access tokens, and (for SPA
     * clients in {@link #WEB_ORIGIN_CLIENTS}) backfills an empty
     * {@code webOrigins} with {@code ["+"]}.
     *
     * <p>Returns a two-element array {@code [lightweightCount, webOriginsCount]}
     * counting clients actually mutated (skipped/missing clients don't count).
     */
    int[] patchSystemClientsInRealm(String realmName) {
        int lightweightCount = 0;
        int webOriginsCount = 0;
        for (String clientId : SYSTEM_CLIENTS) {
            try {
                var uuidOpt = keycloak.findClientUuid(realmName, clientId);
                if (uuidOpt.isEmpty()) {
                    continue;
                }
                boolean[] changed = {false, false};
                keycloak.mutateClient(realmName, uuidOpt.get(), rep -> {
                    changed[0] = applyLightweightTokenDisable(rep);
                    changed[1] = ensureWebOrigins(rep);
                    return changed[0] || changed[1];
                });
                if (changed[0]) lightweightCount++;
                if (changed[1]) webOriginsCount++;
            } catch (Exception e) {
                log.warn("SystemClientTokenBootstrap: failed to patch client '{}' in realm '{}': {}",
                    clientId, realmName, e.getMessage());
            }
        }
        return new int[] {lightweightCount, webOriginsCount};
    }

    /**
     * Sets {@code client.use.lightweight.access.token.enabled=false} on the
     * client. Returns {@code true} if the attribute was missing or had a
     * different value (i.e. a real change); {@code false} if already disabled.
     */
    private boolean applyLightweightTokenDisable(ClientRepresentation rep) {
        java.util.Map<String, String> attrs = rep.getAttributes();
        if (attrs == null) {
            attrs = new java.util.HashMap<>();
            rep.setAttributes(attrs);
        }
        String current = attrs.get(LIGHTWEIGHT_TOKEN_ATTR);
        if ("false".equals(current)) return false;
        attrs.put(LIGHTWEIGHT_TOKEN_ATTR, "false");
        return true;
    }

    /**
     * Backfills {@code webOrigins=["+"]} on SPA system clients whose current
     * {@code webOrigins} is null/empty. Returns {@code true} if the field was
     * mutated; {@code false} if the client isn't an SPA we care about, or its
     * {@code webOrigins} is already non-empty (operator has customised — leave
     * alone).
     */
    private boolean ensureWebOrigins(ClientRepresentation rep) {
        String clientId = rep.getClientId();
        if (!WEB_ORIGIN_CLIENTS.contains(clientId)) {
            return false;
        }
        List<String> current = rep.getWebOrigins();
        if (current != null && !current.isEmpty()) {
            return false;
        }
        rep.setWebOrigins(List.of("+"));
        return true;
    }
}
