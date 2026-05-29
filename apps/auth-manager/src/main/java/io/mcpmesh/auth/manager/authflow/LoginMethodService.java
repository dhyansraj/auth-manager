package io.mcpmesh.auth.manager.authflow;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.IdentityProvidersBootstrap;
import io.mcpmesh.auth.manager.service.TenantService;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Per-tenant login-method toggle: enable / disable the Username Password Form
 * on the tenant's KC login page.
 *
 * <h2>How it works</h2>
 *
 * <p>Implementation is a <b>realm attribute + theme CSS</b> approach: we store
 * a single boolean attribute on the KC realm
 * ({@code mcpmesh.passwordLoginEnabled}), and the {@code mcpmesh-flexible}
 * login theme reads that attribute in {@code template.ftl} and toggles a body
 * class ({@code mcp-no-password}) which hides the username/password form via
 * CSS.
 *
 * <h2>Why not mutate the auth flow?</h2>
 *
 * <p>Earlier versions cloned the built-in {@code browser} flow to
 * {@code mcpmesh-browser} and flipped Username Password Form requirement
 * REQUIRED ↔ DISABLED. Every variation we tried either killed the login-page
 * render (KC's {@code AuthenticationSelectionResolver} NPE'd descending into
 * CONDITIONAL subflows when no user was identified) or fought KC's
 * REQUIRED + ALTERNATIVE rules. We gave up on flow manipulation and moved to
 * UX-only gating.
 *
 * <h2>Security caveat</h2>
 *
 * <p>This is UX gating, NOT server-side enforcement. KC's auth flow remains
 * the default {@code browser} flow, so a determined attacker can still POST
 * username + password to the form-action URL directly. Server-side
 * enforcement would require a custom KC SPI; out of scope.
 *
 * <h2>Invariants</h2>
 *
 * <p>{@link #setPasswordEnabled}{@code (id, false, ...)} still refuses when
 * the tenant has zero enabled IdPs — leaving an operator with zero visible
 * login methods on the page is the failure this guard prevents. Symmetric
 * check in {@link #checkSetIdpEnabled}.
 *
 * <h2>Bootstrap</h2>
 *
 * <p>{@link LoginMethodBootstrap} runs at startup to RESTORE every tenant
 * realm's {@code browserFlow} to KC's built-in {@code browser} — undoing the
 * historical migration to {@code mcpmesh-browser}. The orphaned
 * {@code mcpmesh-browser} flow object is left in place (harmless).
 */
@Service
public class LoginMethodService {

    private static final Logger log = LoggerFactory.getLogger(LoginMethodService.class);

    /**
     * Realm-attribute key read by the theme ({@code template.ftl}) and written
     * by this service. Value is the string {@code "true"} or {@code "false"}.
     * Absence is treated as {@code "true"} (password ON, default).
     */
    public static final String PASSWORD_ENABLED_ATTR = "mcpmesh.passwordLoginEnabled";

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
     * Toggles the realm attribute {@link #PASSWORD_ENABLED_ATTR}. Refuses to
     * disable when no IdPs would remain enabled.
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
            setPasswordAttribute(t.getRealmName(), enabled);
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
     * enabled IdP when password is also DISABLED (i.e. the realm attribute is
     * explicitly {@code "false"}). Called from {@code IdentityProvidersService}
     * before it issues the actual KC mutation.
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
     * Reads the {@link #PASSWORD_ENABLED_ATTR} realm attribute. Defaults to
     * {@code true} (password ON) when the attribute is absent or when the
     * attributes map is null — matching the theme's default.
     */
    public boolean isPasswordEnabled(String realmName) {
        RealmResource realm = kcAdmin.realm(realmName);
        RealmRepresentation rep = realm.toRepresentation();
        Map<String, String> attrs = rep.getAttributes();
        if (attrs == null) return true;
        String val = attrs.get(PASSWORD_ENABLED_ATTR);
        if (val == null) return true;
        return !"false".equalsIgnoreCase(val);
    }

    /**
     * Writes the {@link #PASSWORD_ENABLED_ATTR} realm attribute and PUTs the
     * realm representation back to KC. Copies the existing attribute map to
     * avoid mutating shared state inside the KC client cache.
     */
    private void setPasswordAttribute(String realmName, boolean enabled) {
        RealmResource realm = kcAdmin.realm(realmName);
        RealmRepresentation rep = realm.toRepresentation();
        Map<String, String> attrs = rep.getAttributes() != null
            ? new HashMap<>(rep.getAttributes())
            : new HashMap<>();
        attrs.put(PASSWORD_ENABLED_ATTR, enabled ? "true" : "false");
        rep.setAttributes(attrs);
        realm.update(rep);
        log.info("LoginMethodService: realm '{}' {}={}",
            realmName, PASSWORD_ENABLED_ATTR, enabled);
    }
}
