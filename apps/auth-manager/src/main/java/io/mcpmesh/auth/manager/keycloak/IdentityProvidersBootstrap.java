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
import org.springframework.scheduling.annotation.Scheduled;
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
        new LinkedHashSet<>(java.util.List.of("google", "github", "apple"));

    /** IdP alias for the brokered "Sign in with Apple" provider. */
    public static final String APPLE_ALIAS = "apple";

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
        // Apple is shaped differently (not in asMap) — derive availability from
        // its own creds record.
        if (oauth.apple().isConfigured()) out.add(APPLE_ALIAS);
        return out;
    }

    /** True iff platform creds are configured for the given provider id. */
    public boolean isAvailable(String providerId) {
        if (APPLE_ALIAS.equals(providerId)) {
            return oauth.apple().isConfigured();
        }
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
        if (APPLE_ALIAS.equals(providerId)) {
            return ensureAppleProvider(realm, realmName);
        }
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

    /**
     * Apple-specific ensure path. Unlike google/github, Apple's client secret
     * is a short-lived ES256 JWT that EXPIRES, so this is NOT a create-only
     * idempotent no-op:
     * <ul>
     *   <li>If the apple IdP is missing: create it (rep carries a freshly-minted
     *       JWT + the email importer mapper).</li>
     *   <li>If it already exists: re-mint the JWT and PUT-update the existing
     *       IdP's {@code clientSecret} so the realm never serves a stale secret
     *       across a bootstrap/refresh pass.</li>
     * </ul>
     * Returns true only when a new IdP was created.
     */
    private boolean ensureAppleProvider(RealmResource realm, String realmName) {
        var creds = oauth.apple();
        if (!creds.isConfigured()) {
            log.warn("IdentityProvidersBootstrap: apple creds missing — skipping realm '{}'", realmName);
            return false;
        }

        // The klausbetz SPI mints the client-secret JWT internally from the .p8,
        // so we no longer pre-mint it here — clientSecret carries the raw .p8.

        // Already present? Reconcile. But the provider TYPE can't be changed in
        // place: if the realm still has the legacy generic-"oidc" apple IdP,
        // remove it and recreate as providerId="apple" below. If it's already
        // the SPI provider, just push the desired config (preserving internalId
        // so federated-user links survive).
        try {
            var ipr = realm.identityProviders().get(APPLE_ALIAS);
            IdentityProviderRepresentation existing = ipr.toRepresentation();
            if (!"apple".equals(existing.getProviderId())) {
                ipr.remove();
                log.info("IdentityProvidersBootstrap: removed legacy oidc apple IdP on realm '{}' (migrating to SPI)", realmName);
                // fall through to create the SPI provider
            } else {
                IdentityProviderRepresentation desired = buildAppleRep(creds);
                existing.setConfig(desired.getConfig());
                existing.setTrustEmail(desired.isTrustEmail());
                existing.setStoreToken(desired.isStoreToken());
                existing.setFirstBrokerLoginFlowAlias(desired.getFirstBrokerLoginFlowAlias());
                existing.setDisplayName(desired.getDisplayName());
                ipr.update(existing);
                log.info("IdentityProvidersBootstrap: reconciled apple IdP config on realm '{}'", realmName);
                return false;
            }
        } catch (NotFoundException ignored) {
            // fall through to create
        }

        keycloakAdmin.ensureAutoLinkFlow(realmName);

        IdentityProviderRepresentation rep = buildAppleRep(creds);
        try (Response r = realm.identityProviders().create(rep)) {
            int status = r.getStatus();
            if (status < 200 || status >= 300) {
                throw new RuntimeException(
                    "Keycloak Apple IdP create failed: HTTP " + status + " " + r.getStatusInfo().getReasonPhrase());
            }
        }
        ensureAppleEmailMapper(realm, realmName);
        log.info("IdentityProvidersBootstrap: created IdP 'apple' on realm '{}'", realmName);
        return true;
    }

    /**
     * Idempotently ensures an OIDC attribute-importer mapper that copies the
     * Apple {@code email} claim from the id_token into the brokered user's
     * email, so first-login captures the address. Best-effort; never throws.
     *
     * <p>The klausbetz Apple SPI is configured with scope {@code "name email"}
     * and handles the {@code form_post} callback itself, mapping both email and
     * name from the first POST (see {@link #buildAppleRep}); this mapper just
     * back-stops the email claim from the id_token.
     */
    private void ensureAppleEmailMapper(RealmResource realm, String realmName) {
        try {
            var ipr = realm.identityProviders().get(APPLE_ALIAS);
            for (IdentityProviderMapperRepresentation m : ipr.getMappers()) {
                if ("apple-email-importer".equals(m.getName())) return;
            }
            IdentityProviderMapperRepresentation rep = new IdentityProviderMapperRepresentation();
            rep.setName("apple-email-importer");
            rep.setIdentityProviderAlias(APPLE_ALIAS);
            rep.setIdentityProviderMapper("oidc-user-attribute-idp-mapper");
            Map<String, String> cfg = new HashMap<>();
            cfg.put("claim", "email");
            cfg.put("user.attribute", "email");
            cfg.put("syncMode", "IMPORT");
            rep.setConfig(cfg);
            try (Response resp = ipr.addMapper(rep)) {
                if (resp.getStatus() >= 300) {
                    log.warn("IdentityProvidersBootstrap: apple email mapper add failed on realm '{}': HTTP {}",
                        realmName, resp.getStatus());
                }
            }
        } catch (Exception e) {
            log.warn("IdentityProvidersBootstrap: apple email mapper ensure failed on realm '{}': {}",
                realmName, e.getMessage());
        }
    }

    /**
     * Scheduled reconcile: monthly we walk every realm that has the apple IdP
     * enabled and re-push the SPI config (idempotent reconcile). The klausbetz
     * SPI mints the ES256 client-secret JWT internally per request, so nothing
     * is minted here — this just keeps the apple IdP config in sync across
     * realms. Best-effort; never throws.
     */
    @Scheduled(cron = "${platform.oauth.apple.refresh-cron:0 0 3 1 * *}")
    public void refreshAppleClientSecrets() {
        if (!oauth.apple().isConfigured()) return;
        log.info("IdentityProvidersBootstrap: scheduled apple client-secret refresh starting");
        try {
            String platformRealm = keycloakProps.platform().realm();
            if (platformRealm != null && !platformRealm.isBlank()
                && isEnabled(platformRealm, APPLE_ALIAS)) {
                ensureProvider(admin.realm(platformRealm), platformRealm, APPLE_ALIAS);
            }
        } catch (Exception e) {
            log.warn("IdentityProvidersBootstrap: apple refresh on platform realm failed: {}", e.getMessage());
        }
        try {
            var tenants = tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc();
            for (var t : tenants) {
                String realmName = t.getRealmName();
                if (realmName == null || !realmName.startsWith(TENANT_REALM_PREFIX)) continue;
                try {
                    if (isEnabled(realmName, APPLE_ALIAS)) {
                        ensureProvider(admin.realm(realmName), realmName, APPLE_ALIAS);
                    }
                } catch (Exception e) {
                    log.warn("IdentityProvidersBootstrap: apple refresh failed for realm '{}': {}",
                        realmName, e.getMessage());
                }
            }
        } catch (Exception e) {
            log.warn("IdentityProvidersBootstrap: apple scheduled refresh aborted: {}", e.getMessage());
        }
    }

    /**
     * Builds the Apple IdP representation. Apple is brokered via the klausbetz
     * Apple SPI (providerId {@code "apple"}). We request scope
     * {@code "name email"}, which drives {@code response_mode=form_post}; the
     * SPI handles the POST callback and mints the ES256 client-secret JWT
     * internally from the raw {@code .p8} (config key {@code clientSecret}
     * carries the raw {@code .p8}, NOT a pre-minted JWT).
     *
     * <p>CRITICAL: no {@code userInfoUrl} is set — Apple has NO userinfo
     * endpoint; all claims come from the id_token (validated via JWKS).
     */
    private static IdentityProviderRepresentation buildAppleRep(
        PlatformOAuthProperties.AppleProvider creds
    ) {
        IdentityProviderRepresentation rep = new IdentityProviderRepresentation();
        rep.setAlias(APPLE_ALIAS);
        // The klausbetz Apple SPI (providerId="apple"), NOT KC's generic "oidc"
        // broker. Apple requires response_mode=form_post when the email/name
        // scope is requested, which makes it POST the code back — and KC's
        // generic OIDC broker endpoint has NO @POST handler (returns 405). This
        // SPI adds the form_post POST handler, mints the ES256 client-secret
        // JWT internally from the .p8, maps email/name, and renders the Apple
        // logo. See dev/keycloak/Dockerfile (the JAR is baked into the KC image).
        rep.setProviderId("apple");
        rep.setEnabled(true);
        rep.setTrustEmail(true);
        rep.setStoreToken(false);
        rep.setAddReadTokenRoleOnCreate(false);
        rep.setFirstBrokerLoginFlowAlias(KeycloakAdminService.FIRST_BROKER_LOGIN_AUTOLINK);
        rep.setDisplayName("Continue with Apple");

        // Extension config keys (klausbetz v1.15.0):
        //   clientId     = Apple Services ID
        //   teamId/keyId = from the Apple Developer account
        //   clientSecret = the RAW .p8 private-key contents (the SPI mints the
        //                  short-lived ES256 JWT from it per request — so this
        //                  is the static key, not a pre-minted JWT)
        //   defaultScope = "name email" → drives form_post; email + name on
        //                  first login.
        Map<String, String> config = new LinkedHashMap<>();
        config.put("clientId", creds.servicesId());
        config.put("teamId", creds.teamId());
        config.put("keyId", creds.keyId());
        config.put("clientSecret", creds.privateKey());
        config.put("defaultScope", "name email");
        config.put("syncMode", "IMPORT");
        rep.setConfig(config);
        return rep;
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
        m.put("apple", "Apple");
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
