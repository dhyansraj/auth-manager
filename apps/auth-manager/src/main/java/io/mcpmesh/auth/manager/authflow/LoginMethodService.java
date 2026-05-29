package io.mcpmesh.auth.manager.authflow;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.IdentityProvidersBootstrap;
import io.mcpmesh.auth.manager.service.TenantService;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Per-tenant login-method toggle: enable / disable the Username Password Form
 * step in the cloned {@code mcpmesh-browser} authentication flow.
 *
 * <h2>How it works</h2>
 *
 * <p>KC's built-in {@code browser} flow is shared across all realms in the
 * KC server and cannot be edited in-place. The first time we want to flip
 * password OFF on a tenant, we clone {@code browser} → {@code mcpmesh-browser}
 * via the KC admin API, point the realm's {@code browserFlow} at the clone,
 * and then mutate the clone's Username Password Form execution requirement
 * (REQUIRED ↔ DISABLED).
 *
 * <h2>Invariants</h2>
 *
 * <p>{@link #setPasswordEnabled}{@code (id, false, ...)} refuses when the
 * tenant has zero enabled IdPs — locking yourself out of a fresh tenant is
 * the entire failure mode this guard prevents. Symmetric check in
 * {@link #checkSetIdpEnabled}: disabling the last IdP refuses when password
 * is also off.
 *
 * <h2>Bootstrap</h2>
 *
 * <p>{@link LoginMethodBootstrap} runs at startup to migrate existing tenant
 * realms from the built-in {@code browser} to {@code mcpmesh-browser} —
 * preserving the current state (Username Password Form stays REQUIRED).
 * After this, every tenant realm's {@code browserFlow} points at our
 * private clone, so toggle calls don't need a per-tenant first-run check.
 */
@Service
public class LoginMethodService {

    private static final Logger log = LoggerFactory.getLogger(LoginMethodService.class);

    /** KC's built-in browser flow alias — what every realm uses by default. */
    public static final String BUILTIN_BROWSER_FLOW = "browser";

    /** Our cloned flow's alias — where the password-toggle mutation happens. */
    public static final String MCPMESH_BROWSER_FLOW = "mcpmesh-browser";

    /**
     * The display name KC assigns to the Username Password Form leaf execution
     * inside the Forms subflow of the standard browser flow. Stable across KC
     * versions (we tested against 26.x).
     */
    public static final String USERNAME_PASSWORD_EXECUTION = "Username Password Form";

    private static final ActorKind ACTOR_KIND = ActorKind.USER;

    private final TenantService tenants;
    private final Keycloak kcAdmin;
    private final IdentityProvidersBootstrap idp;
    private final AuditService audit;

    public LoginMethodService(TenantService tenants,
                              Keycloak kcAdmin,
                              IdentityProvidersBootstrap idp,
                              AuditService audit) {
        this.tenants = tenants;
        this.kcAdmin = kcAdmin;
        this.idp = idp;
        this.audit = audit;
    }

    public LoginMethodStatus get(UUID tenantId) {
        Tenant t = tenants.get(tenantId);
        boolean pwd = isPasswordEnabled(t.getRealmName());
        List<String> idps = List.copyOf(idp.listEnabledProviders(t.getRealmName()));
        return new LoginMethodStatus(pwd, idps);
    }

    /**
     * Flips the Username Password Form execution's requirement. Clones the
     * built-in browser flow on first call if needed; idempotent on subsequent
     * calls. Refuses to disable when no IdPs would remain enabled.
     */
    public LoginMethodStatus setPasswordEnabled(UUID tenantId, boolean enabled, String actor) {
        Tenant t = tenants.get(tenantId);
        return setPasswordEnabledForTenant(t, enabled, actor);
    }

    /**
     * Same as {@link #setPasswordEnabled} but takes a {@link Tenant} directly —
     * used by {@code TenantController.create()} where we have the entity in
     * hand and don't want to re-load it.
     */
    public LoginMethodStatus setPasswordEnabledForTenant(Tenant t, boolean enabled, String actor) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("tenant_slug", t.getSlug());
        details.put("realm", t.getRealmName());
        details.put("enabled", enabled);

        if (!enabled) {
            int idpCount = idp.listEnabledProviders(t.getRealmName()).size();
            if (idpCount == 0) {
                var ex = new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "login.no_methods_remaining: cannot disable password — at least one identity provider must be enabled");
                audit.recordFailure(actor, ACTOR_KIND, t.getId(),
                    "tenant.login_methods.set_password", "tenant", t.getId().toString(),
                    Map.of("enabled", false), ex, details);
                throw ex;
            }
        }

        try {
            ensureClonedFlow(t.getRealmName());
            mutatePasswordRequirement(t.getRealmName(), enabled);
        } catch (Exception e) {
            audit.recordFailure(actor, ACTOR_KIND, t.getId(),
                "tenant.login_methods.set_password", "tenant", t.getId().toString(),
                Map.of("enabled", enabled), e, details);
            throw e instanceof RuntimeException re ? re : new RuntimeException(e);
        }

        audit.recordSuccess(actor, ACTOR_KIND, t.getId(),
            "tenant.login_methods.set_password", "tenant", t.getId().toString(),
            Map.of("enabled", enabled), details);

        return get(t.getId());
    }

    /**
     * Symmetric guard for the IdP toggle path: refuses to disable the last
     * enabled IdP when password is also DISABLED. Called from
     * {@code IdentityProvidersService} before it issues the actual KC mutation.
     *
     * @param wantEnabled the desired new state of the IdP; only the {@code false}
     *                    path performs the check.
     * @throws ResponseStatusException 400 with code {@code login.no_methods_remaining}
     *         when disabling this IdP would leave zero login methods enabled.
     */
    public void checkSetIdpEnabled(UUID tenantId, String providerAlias, boolean wantEnabled) {
        if (wantEnabled) return;
        Tenant t = tenants.get(tenantId);
        String realm = t.getRealmName();
        boolean pwd = isPasswordEnabled(realm);
        if (pwd) return;  // password covers us; IdP can go.
        var enabled = idp.listEnabledProviders(realm);
        // Removing self leaves 0 IdPs?
        long remaining = enabled.stream()
            .filter(a -> !a.equalsIgnoreCase(providerAlias))
            .count();
        if (remaining == 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "login.no_methods_remaining: cannot disable last identity provider — re-enable "
                    + "username/password first or enable another provider");
        }
    }

    /**
     * Migration entry point: clones the realm's browser flow to
     * {@code mcpmesh-browser} if not already cloned, preserving current
     * Username Password Form state. Idempotent — safe to call repeatedly.
     *
     * @return true if a clone was issued; false if the realm was already on
     *         {@code mcpmesh-browser}.
     */
    public boolean ensureClonedFlow(String realmName) {
        RealmResource realm = kcAdmin.realm(realmName);
        RealmRepresentation rep = realm.toRepresentation();
        if (MCPMESH_BROWSER_FLOW.equals(rep.getBrowserFlow())) {
            return false;  // already migrated
        }
        AuthenticationManagementResource flows = realm.flows();
        // Defensive: copy() returns 409 if the alias already exists. Check first.
        boolean cloneExists = flows.getFlows().stream()
            .anyMatch(f -> MCPMESH_BROWSER_FLOW.equals(f.getAlias()));
        if (!cloneExists) {
            Map<String, Object> copyBody = new LinkedHashMap<>();
            copyBody.put("newName", MCPMESH_BROWSER_FLOW);
            try (var resp = flows.copy(BUILTIN_BROWSER_FLOW, copyBody)) {
                int status = resp.getStatus();
                if (status >= 300) {
                    throw new RuntimeException(
                        "KC flow copy failed: HTTP " + status + " " + resp.getStatusInfo().getReasonPhrase());
                }
            }
            log.info("LoginMethodService: cloned 'browser' → '{}' on realm '{}'",
                MCPMESH_BROWSER_FLOW, realmName);
        }
        rep.setBrowserFlow(MCPMESH_BROWSER_FLOW);
        realm.update(rep);
        log.info("LoginMethodService: realm '{}' browserFlow now points at '{}'",
            realmName, MCPMESH_BROWSER_FLOW);
        return true;
    }

    /**
     * Reads the password-form execution's requirement off the
     * {@code mcpmesh-browser} flow (if present) or the built-in
     * {@code browser} flow as a fallback. Returns true when the requirement
     * is {@code REQUIRED} or {@code ALTERNATIVE}; false when {@code DISABLED}.
     */
    public boolean isPasswordEnabled(String realmName) {
        RealmResource realm = kcAdmin.realm(realmName);
        String flowAlias = realm.toRepresentation().getBrowserFlow();
        if (flowAlias == null || flowAlias.isBlank()) flowAlias = BUILTIN_BROWSER_FLOW;
        try {
            for (AuthenticationExecutionInfoRepresentation exec :
                    realm.flows().getExecutions(flowAlias)) {
                if (USERNAME_PASSWORD_EXECUTION.equals(exec.getDisplayName())) {
                    String req = exec.getRequirement();
                    return "REQUIRED".equals(req) || "ALTERNATIVE".equals(req);
                }
            }
        } catch (Exception e) {
            log.warn("isPasswordEnabled({}) — getExecutions({}) failed: {}",
                realmName, flowAlias, e.getMessage());
            return true;  // safe default: assume on
        }
        // No password execution at all? Definitely not enabled.
        return false;
    }

    private void mutatePasswordRequirement(String realmName, boolean enabled) {
        RealmResource realm = kcAdmin.realm(realmName);
        var executions = realm.flows().getExecutions(MCPMESH_BROWSER_FLOW);
        AuthenticationExecutionInfoRepresentation match = null;
        for (var exec : executions) {
            if (USERNAME_PASSWORD_EXECUTION.equals(exec.getDisplayName())) {
                match = exec;
                break;
            }
        }
        if (match == null) {
            throw new RuntimeException(
                "Cannot find '" + USERNAME_PASSWORD_EXECUTION + "' execution in flow "
                    + MCPMESH_BROWSER_FLOW + " on realm " + realmName);
        }
        String want = enabled ? "REQUIRED" : "DISABLED";
        if (want.equals(match.getRequirement())) {
            log.debug("LoginMethodService: realm '{}' password requirement already '{}'", realmName, want);
            return;
        }
        match.setRequirement(want);
        realm.flows().updateExecutions(MCPMESH_BROWSER_FLOW, match);
        log.info("LoginMethodService: realm '{}' Username Password Form requirement → '{}'",
            realmName, want);
    }
}
