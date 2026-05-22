package io.mcpmesh.auth.manager.keycloak;

import io.mcpmesh.auth.manager.persistence.TenantRepository;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

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

    /**
     * KC's default first-broker-login flow alias. Created automatically with
     * every realm; we reference it by name so KC links / creates accounts
     * appropriately on the first social login.
     */
    private static final String FIRST_BROKER_LOGIN_FLOW = "first broker login";

    /** Realm-name prefix used by tenant realms (see TenantService). */
    private static final String TENANT_REALM_PREFIX = "t-";

    private final Keycloak admin;
    private final PlatformOAuthProperties oauth;
    private final TenantRepository tenantRepo;

    public IdentityProvidersBootstrap(Keycloak admin,
                                      PlatformOAuthProperties oauth,
                                      TenantRepository tenantRepo) {
        this.admin = admin;
        this.oauth = oauth;
        this.tenantRepo = tenantRepo;
    }

    /**
     * Backfill on startup: for every active tenant realm, ensure the default
     * provider set is configured. Logs a one-liner per realm + provider;
     * never throws (best-effort).
     */
    @Override
    public void run(ApplicationArguments args) {
        Set<String> configured = configuredProviders();
        if (configured.isEmpty()) {
            log.info("IdentityProvidersBootstrap: no platform OAuth creds configured — skipping backfill");
            return;
        }
        try {
            var tenants = tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc();
            for (var t : tenants) {
                String realmName = t.getRealmName();
                if (realmName == null || !realmName.startsWith(TENANT_REALM_PREFIX)) continue;
                try {
                    ensureProviders(realmName, configured);
                } catch (Exception e) {
                    log.warn("IdentityProvidersBootstrap: backfill failed for realm '{}': {}",
                        realmName, e.getMessage());
                }
            }
        } catch (Exception e) {
            log.warn("IdentityProvidersBootstrap: startup backfill aborted: {}", e.getMessage());
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
        rep.setFirstBrokerLoginFlowAlias(FIRST_BROKER_LOGIN_FLOW);

        Map<String, String> config = new LinkedHashMap<>();
        config.put("clientId", creds.clientId());
        config.put("clientSecret", creds.clientSecret());
        config.put("syncMode", "IMPORT");
        // The display name fields KC uses for the login-page button. KC supplies
        // sensible defaults from the provider template, but we set them explicitly
        // so the button looks consistent across realms.
        if ("google".equals(providerId)) {
            rep.setDisplayName("Google");
        } else if ("github".equals(providerId)) {
            rep.setDisplayName("GitHub");
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
