package io.mcpmesh.auth.manager.keycloak;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Per-realm Keycloak IdP brokering bootstrap for platform-level OAuth
 * providers (Google + GitHub).
 *
 * <p>One OAuth app per provider is registered at the provider (Google,
 * GitHub) and its credentials are read from env vars via
 * {@link PlatformOAuthProperties}. Each tenant realm gets a KC
 * {@code identity-provider/instances} entry pointing at those creds; KC
 * renders the corresponding social-login button on the realm's login page.
 *
 * <p>This bootstrap is also a startup hook ({@link ApplicationRunner}): on
 * each boot we iterate existing non-system realms and call
 * {@link #ensureProviders(String, Set)} so new providers (or freshly-added
 * platform creds) propagate to all tenants without an explicit backfill.
 * Idempotent — already-configured realms are no-op.
 */
@Component
public class IdentityProvidersBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(IdentityProvidersBootstrap.class);

    public static final Set<String> SUPPORTED_PROVIDERS =
        new LinkedHashSet<>(java.util.List.of("google", "github"));

    /** Realm-name prefix used by tenant realms (see TenantService). */
    private static final String TENANT_REALM_PREFIX = "t-";

    private final Keycloak admin;
    private final PlatformOAuthProperties oauth;
    private final TenantRepository tenantRepo;
    private final KeycloakAdminService keycloakAdmin;
    private final KeycloakProperties keycloakProps;

    public IdentityProvidersBootstrap(Keycloak admin,
                                      PlatformOAuthProperties oauth,
                                      TenantRepository tenantRepo,
                                      KeycloakAdminService keycloakAdmin,
                                      KeycloakProperties keycloakProps) {
        this.admin = admin;
        this.oauth = oauth;
        this.tenantRepo = tenantRepo;
        this.keycloakAdmin = keycloakAdmin;
        this.keycloakProps = keycloakProps;
    }

    /**
     * Backfill on startup: for every active tenant realm, ensure the default
     * provider set is configured. Logs a one-liner per realm + provider;
     * never throws (best-effort).
     */
    @Override
    public void run(ApplicationArguments args) {
        Set<String> configured = configuredProviders();

        // Re-point existing IdPs (tenant + platform realms) at the auto-link
        // first-broker-login flow even when no creds are configured: existing
        // realms may already carry IdPs from a previous deploy.
        try {
            String platformRealm = keycloakProps.platform().realm();
            if (platformRealm != null && !platformRealm.isBlank()) {
                repointIdpsToAutoLink(platformRealm);
            }
        } catch (Exception e) {
            log.warn("IdentityProvidersBootstrap: platform-realm auto-link repoint aborted: {}", e.getMessage());
        }

        try {
            var tenants = tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc();
            for (var t : tenants) {
                String realmName = t.getRealmName();
                if (realmName == null || !realmName.startsWith(TENANT_REALM_PREFIX)) continue;
                repointIdpsToAutoLink(realmName);
                // Re-assert the persisted invite-only posture: ensureAutoLinkFlow
                // leaves create-if-unique at the default ALTERNATIVE, so a
                // redeploy would silently re-open an invite-only tenant unless we
                // reconcile here. Best-effort; never throw out of run().
                try {
                    keycloakAdmin.setInviteOnly(realmName, t.isInviteOnly());
                } catch (Exception e) {
                    log.warn("IdentityProvidersBootstrap: invite-only reconcile failed for realm '{}': {}",
                        realmName, e.getMessage());
                }
                if (configured.isEmpty()) continue;
                try {
                    ensureProviders(t, configured);
                } catch (Exception e) {
                    log.warn("IdentityProvidersBootstrap: backfill failed for realm '{}': {}",
                        realmName, e.getMessage());
                }
            }
        } catch (Exception e) {
            log.warn("IdentityProvidersBootstrap: startup backfill aborted: {}", e.getMessage());
        }

        if (configured.isEmpty()) {
            log.info("IdentityProvidersBootstrap: no platform OAuth creds configured — skipped IdP create backfill");
        }
    }

    /**
     * Ensures the auto-link first-broker-login flow exists on the realm and
     * re-points every IdP that still references the built-in "first broker
     * login" flow (or has no flow set) at it. Idempotent and best-effort:
     * never throws — logs a warn and continues on any per-IdP failure.
     */
    public void repointIdpsToAutoLink(String realmName) {
        String alias;
        try {
            alias = keycloakAdmin.ensureAutoLinkFlow(realmName);
        } catch (NotFoundException e) {
            log.warn("IdentityProvidersBootstrap: realm '{}' not found — skipping auto-link repoint", realmName);
            return;
        } catch (Exception e) {
            log.warn("IdentityProvidersBootstrap: ensureAutoLinkFlow failed for realm '{}': {}",
                realmName, e.getMessage());
            return;
        }

        List<IdentityProviderRepresentation> providers;
        try {
            providers = admin.realm(realmName).identityProviders().findAll();
        } catch (Exception e) {
            log.warn("IdentityProvidersBootstrap: listing IdPs failed for realm '{}': {}",
                realmName, e.getMessage());
            return;
        }
        for (IdentityProviderRepresentation rep : providers) {
            try {
                String current = rep.getFirstBrokerLoginFlowAlias();
                if (current == null || current.isBlank()
                    || KeycloakAdminService.FIRST_BROKER_LOGIN_FLOW.equals(current)) {
                    rep.setFirstBrokerLoginFlowAlias(alias);
                    admin.realm(realmName).identityProviders().get(rep.getAlias()).update(rep);
                    log.info("IdentityProvidersBootstrap: re-pointed IdP '{}' in realm '{}' at auto-link flow",
                        rep.getAlias(), realmName);
                }
            } catch (Exception e) {
                log.warn("IdentityProvidersBootstrap: repoint IdP '{}' in realm '{}' failed: {}",
                    rep.getAlias(), realmName, e.getMessage());
            }
        }
    }

    /** Provider ids whose platform creds are configured (env vars set). */
    public Set<String> configuredProviders() {
        Set<String> out = new LinkedHashSet<>();
        for (var e : oauth.asMap().entrySet()) {
            if (e.getValue().isConfigured()) out.add(e.getKey());
        }
        return out;
    }

    /** True iff platform creds are configured for the given provider id. */
    public boolean isAvailable(String providerId) {
        var p = oauth.asMap().get(providerId);
        return p != null && p.isConfigured();
    }

    /**
     * Ensures the given providers exist as IdP instances on the given realm.
     * For each provider:
     *   - If creds missing: WARN + skip
     *   - If already present (by alias): no-op
     *   - Else: create the IdP instance with platform defaults
     * Never throws; logs and continues on a per-provider basis.
     *
     * <p>This overload does NOT consult the operator-disabled set — use it
     * only for explicit create paths (e.g. new-tenant provisioning, manifest
     * apply) where the caller has decided the alias should exist. The
     * {@link #ensureProviders(Tenant, Set)} overload filters disabled aliases
     * and is what startup backfill / restart-safe paths must use.
     */
    public void ensureProviders(String realmName, Set<String> enabledProviders) {
        if (enabledProviders == null || enabledProviders.isEmpty()) return;
        RealmResource realm;
        try {
            realm = admin.realm(realmName);
            realm.toRepresentation();
        } catch (NotFoundException e) {
            log.warn("IdentityProvidersBootstrap: realm '{}' not found — skipping ensureProviders", realmName);
            return;
        } catch (Exception e) {
            log.warn("IdentityProvidersBootstrap: realm '{}' unreachable ({}) — skipping",
                realmName, e.getMessage());
            return;
        }

        for (String providerId : enabledProviders) {
            try {
                ensureProvider(realm, realmName, providerId);
            } catch (Exception e) {
                log.warn("IdentityProvidersBootstrap: ensure '{}' on realm '{}' failed: {}",
                    providerId, realmName, e.getMessage());
            }
        }
    }

    /**
     * Tenant-aware overload: same as {@link #ensureProviders(String, Set)}
     * but filters out aliases the operator has explicitly disabled (recorded
     * on {@code tenant.settings.disabledIdps}). This is the form startup
     * backfill must use so a re-deploy doesn't resurrect IdPs the operator
     * already removed via the admin UI.
     */
    public void ensureProviders(Tenant tenant, Set<String> configured) {
        if (tenant == null) return;
        if (configured == null || configured.isEmpty()) return;
        Set<String> disabled = tenant.getDisabledIdps();
        Set<String> effective = new LinkedHashSet<>();
        for (String alias : configured) {
            if (disabled.contains(alias.toLowerCase(java.util.Locale.ROOT))) {
                log.debug("IdentityProvidersBootstrap: realm '{}' skipping disabled IdP '{}'",
                    tenant.getRealmName(), alias);
                continue;
            }
            effective.add(alias);
        }
        if (effective.isEmpty()) return;
        ensureProviders(tenant.getRealmName(), effective);
    }

    /**
     * Adds a single IdP instance to the realm. Returns true if a new instance
     * was created; false if creds were missing or the alias already exists.
     */
    public boolean addProvider(String realmName, String providerId) {
        if (!SUPPORTED_PROVIDERS.contains(providerId)) {
            throw new IllegalArgumentException("Unsupported provider: " + providerId);
        }
        if (!isAvailable(providerId)) {
            throw new IllegalStateException("Provider creds not configured: " + providerId);
        }
        RealmResource realm = admin.realm(realmName);
        return ensureProvider(realm, realmName, providerId);
    }

    /**
     * Removes the IdP instance for the given provider id from the realm.
     * Returns true if it was present and removed; false if it didn't exist.
     */
    public boolean removeProvider(String realmName, String providerId) {
        if (!SUPPORTED_PROVIDERS.contains(providerId)) {
            throw new IllegalArgumentException("Unsupported provider: " + providerId);
        }
        RealmResource realm = admin.realm(realmName);
        try {
            IdentityProviderResource ipr = realm.identityProviders().get(providerId);
            ipr.toRepresentation();  // throws NotFoundException if missing
            ipr.remove();
            log.info("IdentityProvidersBootstrap: removed IdP '{}' from realm '{}'", providerId, realmName);
            return true;
        } catch (NotFoundException e) {
            return false;
        }
    }

    /** True if the given alias has an IdP instance in the realm. */
    public boolean isEnabled(String realmName, String providerId) {
        try {
            admin.realm(realmName).identityProviders().get(providerId).toRepresentation();
            return true;
        } catch (NotFoundException e) {
            return false;
        } catch (Exception e) {
            log.debug("isEnabled({}, {}) probe failed: {}", realmName, providerId, e.getMessage());
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Mapper management (Hardcoded Realm Role IdP mappers)
    // -------------------------------------------------------------------------

    /** Returns the set of IdP aliases currently enabled on the realm. */
    public Set<String> listEnabledProviders(String realmName) {
        try {
            return admin.realm(realmName).identityProviders().findAll().stream()
                .map(IdentityProviderRepresentation::getAlias)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        } catch (Exception e) {
            log.warn("listEnabledProviders({}) failed: {}", realmName, e.getMessage());
            return Set.of();
        }
    }

    /**
     * Idempotently ensures a Hardcoded Realm Role IdP mapper on the given
     * provider that assigns the given realm role at first broker login.
     * Returns true if a new mapper was created; false if it already existed.
     * Sync mode IMPORT: role added only on first broker login, mutable
     * per-user thereafter.
     */
    public boolean ensureHardcodedRoleMapper(String realmName, String providerAlias, String roleName) {
        IdentityProviderResource ipr = admin.realm(realmName).identityProviders().get(providerAlias);
        String mapperName = "hardcoded-role-" + roleName;
        for (IdentityProviderMapperRepresentation m : ipr.getMappers()) {
            if (mapperName.equals(m.getName())
                && "oidc-hardcoded-role-idp-mapper".equals(m.getIdentityProviderMapper())
                && m.getConfig() != null
                && roleName.equals(m.getConfig().get("role"))) {
                return false;
            }
        }
        IdentityProviderMapperRepresentation rep = new IdentityProviderMapperRepresentation();
        rep.setName(mapperName);
        rep.setIdentityProviderAlias(providerAlias);
        rep.setIdentityProviderMapper("oidc-hardcoded-role-idp-mapper");
        Map<String, String> cfg = new HashMap<>();
        cfg.put("role", roleName);
        cfg.put("syncMode", "IMPORT");
        rep.setConfig(cfg);
        try (jakarta.ws.rs.core.Response resp = ipr.addMapper(rep)) {
            if (resp.getStatus() >= 300) {
                log.warn("ensureHardcodedRoleMapper({}, {}, {}) failed: HTTP {}",
                    realmName, providerAlias, roleName, resp.getStatus());
                return false;
            }
        }
        log.info("ensureHardcodedRoleMapper: added '{}' on IdP '{}' in realm '{}'",
            mapperName, providerAlias, realmName);
        return true;
    }

    /**
     * Idempotently removes the Hardcoded Role mapper assigning the given role
     * on the given IdP. Returns true if it was present and removed.
     */
    public boolean removeHardcodedRoleMapper(String realmName, String providerAlias, String roleName) {
        IdentityProviderResource ipr = admin.realm(realmName).identityProviders().get(providerAlias);
        for (IdentityProviderMapperRepresentation m : ipr.getMappers()) {
            if ("oidc-hardcoded-role-idp-mapper".equals(m.getIdentityProviderMapper())
                && m.getConfig() != null
                && roleName.equals(m.getConfig().get("role"))) {
                ipr.delete(m.getId());
                log.info("removeHardcodedRoleMapper: dropped role '{}' mapper on IdP '{}' in realm '{}'",
                    roleName, providerAlias, realmName);
                return true;
            }
        }
        return false;
    }

    /** Returns the set of realm role names assigned by Hardcoded Role mappers on the given IdP. */
    public Set<String> listHardcodedRoles(String realmName, String providerAlias) {
        try {
            IdentityProviderResource ipr = admin.realm(realmName).identityProviders().get(providerAlias);
            Set<String> out = new LinkedHashSet<>();
            for (IdentityProviderMapperRepresentation m : ipr.getMappers()) {
                if ("oidc-hardcoded-role-idp-mapper".equals(m.getIdentityProviderMapper())
                    && m.getConfig() != null) {
                    String r = m.getConfig().get("role");
                    if (r != null && !r.isBlank()) out.add(r);
                }
            }
            return out;
        } catch (Exception e) {
            log.warn("listHardcodedRoles({}, {}) failed: {}", realmName, providerAlias, e.getMessage());
            return Set.of();
        }
    }

    // -------------------------------------------------------------------------
    // internals
    // -------------------------------------------------------------------------

    private boolean ensureProvider(RealmResource realm, String realmName, String providerId) {
        var creds = oauth.asMap().get(providerId);
        if (creds == null || !creds.isConfigured()) {
            log.warn("IdentityProvidersBootstrap: '{}' creds missing — skipping realm '{}'",
                providerId, realmName);
            return false;
        }
        // Already present? Idempotent no-op.
        try {
            realm.identityProviders().get(providerId).toRepresentation();
            log.debug("IdentityProvidersBootstrap: IdP '{}' already exists in realm '{}'",
                providerId, realmName);
            return false;
        } catch (NotFoundException ignored) {
            // fall through to create
        }

        // Ensure the auto-link first-broker-login flow exists before the IdP
        // references it (buildRep points the IdP at this flow alias).
        keycloakAdmin.ensureAutoLinkFlow(realmName);

        IdentityProviderRepresentation rep = buildRep(providerId, creds);
        try (Response r = realm.identityProviders().create(rep)) {
            int status = r.getStatus();
            if (status < 200 || status >= 300) {
                throw new RuntimeException(
                    "Keycloak IdP create failed: HTTP " + status + " " + r.getStatusInfo().getReasonPhrase());
            }
        }
        log.info("IdentityProvidersBootstrap: created IdP '{}' on realm '{}'", providerId, realmName);
        return true;
    }

    private static IdentityProviderRepresentation buildRep(
        String providerId, PlatformOAuthProperties.Provider creds
    ) {
        IdentityProviderRepresentation rep = new IdentityProviderRepresentation();
        rep.setAlias(providerId);
        rep.setProviderId(providerId);
        rep.setEnabled(true);
        rep.setTrustEmail(true);
        rep.setStoreToken(false);
        rep.setAddReadTokenRoleOnCreate(false);
        rep.setFirstBrokerLoginFlowAlias(KeycloakAdminService.FIRST_BROKER_LOGIN_AUTOLINK);

        Map<String, String> config = new LinkedHashMap<>();
        config.put("clientId", creds.clientId());
        config.put("clientSecret", creds.clientSecret());
        config.put("syncMode", "IMPORT");
        // The display name fields KC uses for the login-page button. KC supplies
        // sensible defaults from the provider template, but we set them explicitly
        // so the button looks consistent across realms.
        if ("google".equals(providerId)) {
            rep.setDisplayName("Continue with Google");
        } else if ("github".equals(providerId)) {
            rep.setDisplayName("Continue with GitHub");
        }
        rep.setConfig(config);
        return rep;
    }

    /** Convenience: providers we care about (Google + GitHub) as an ordered map of id -> default display. */
    public static Map<String, String> defaultDisplayNames() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("google", "Google");
        m.put("github", "GitHub");
        return m;
    }

    /** Default provider set new tenants get on create — only those with configured creds. */
    public Set<String> defaultProvidersForNewTenant() {
        Set<String> out = new LinkedHashSet<>();
        for (String p : SUPPORTED_PROVIDERS) {
            if (isAvailable(p)) out.add(p);
        }
        return out;
    }
}
