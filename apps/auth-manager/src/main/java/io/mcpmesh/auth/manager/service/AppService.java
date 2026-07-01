package io.mcpmesh.auth.manager.service;

import io.mcpmesh.auth.manager.api.dto.CreateAppRequest;
import io.mcpmesh.auth.manager.api.dto.CreateAppRequest.AppProfile;
import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.app.App;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.domain.tenant.TenantStatus;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.keycloak.KeycloakProperties;
import io.mcpmesh.auth.manager.persistence.AppRepository;
import io.mcpmesh.auth.manager.persistence.TenantHostnameRepository;
import io.mcpmesh.auth.manager.service.exception.AppConflictException;
import io.mcpmesh.auth.manager.service.exception.AppNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
@Transactional
public class AppService {

    private static final Logger log = LoggerFactory.getLogger(AppService.class);

    private static final String SYSTEM_ACTOR = "system";
    private static final ActorKind SYSTEM_KIND = ActorKind.SERVICE;

    private final AppRepository repo;
    private final TenantService tenants;
    private final TenantHostnameRepository hostnameRepo;
    private final KeycloakAdminService keycloak;
    private final KeycloakProperties kcProps;
    private final AuditService audit;

    public AppService(
        AppRepository repo,
        TenantService tenants,
        TenantHostnameRepository hostnameRepo,
        KeycloakAdminService keycloak,
        KeycloakProperties kcProps,
        AuditService audit
    ) {
        this.repo = repo;
        this.tenants = tenants;
        this.hostnameRepo = hostnameRepo;
        this.keycloak = keycloak;
        this.kcProps = kcProps;
        this.audit = audit;
    }

    /**
     * Creates an OIDC client in the tenant's realm and persists an App row.
     * Returns the created App and the client secret (operator-visible once for
     * confidential clients; null for public SPA clients).
     *
     * <p>Branches on {@link CreateAppRequest#profile()} after KC client
     * creation to install the right KC mutations for the chosen profile
     * (SPA_PKCE flips public + PKCE-S256; SERVICE_ACCOUNT_ONLY disables
     * standard / direct grants; CONFIDENTIAL_BACKEND is the default no-op
     * since {@link KeycloakAdminService#createClient} already lands in that
     * shape).
     */
    public AppCreationResult create(UUID tenantId, CreateAppRequest req, String actor) {
        String slug = req.slug();
        String displayName = req.displayName();
        AppProfile profile = req.profile() == null ? AppProfile.CONFIDENTIAL_BACKEND : req.profile();

        Tenant tenant = tenants.get(tenantId);  // 404 if not found / deleted
        if (tenant.getStatus() != TenantStatus.ACTIVE) {
            throw new IllegalStateException(
                "Cannot create app in tenant with status " + tenant.getStatus());
        }
        if (repo.existsByTenantIdAndSlug(tenantId, slug)) {
            audit.recordFailure(SYSTEM_ACTOR, SYSTEM_KIND, tenantId,
                "app.create", "app", null,
                Map.of("tenantSlug", tenant.getSlug(), "appSlug", slug),
                new AppConflictException(tenant.getSlug(), slug),
                Map.of("reason", "slug_conflict"));
            throw new AppConflictException(tenant.getSlug(), slug);
        }

        String realmName = tenant.getRealmName();
        String clientUuid;
        try {
            // Idempotency: if a previous failed attempt already created the KC client,
            // look it up rather than failing.
            clientUuid = findOrCreateClientWithRetry(realmName, slug, displayName);
        } catch (Exception e) {
            audit.recordFailure(SYSTEM_ACTOR, SYSTEM_KIND, tenantId,
                "app.create", "app", null,
                Map.of("tenantSlug", tenant.getSlug(), "appSlug", slug),
                e,
                Map.of("reason", "keycloak_create_failed"));
            throw new RuntimeException("Keycloak client creation failed: " + e.getMessage(), e);
        }

        // Profile-specific KC mutations. All idempotent so re-running this
        // method on a recovered app row produces the same KC state.
        try {
            applyProfile(profile, tenant, slug, clientUuid, req.iosBundleId());
        } catch (Exception e) {
            audit.recordFailure(SYSTEM_ACTOR, SYSTEM_KIND, tenantId,
                "app.create", "app", null,
                Map.of("tenantSlug", tenant.getSlug(), "appSlug", slug, "profile", profile.name()),
                e,
                Map.of("reason", "keycloak_profile_apply_failed"));
            throw new RuntimeException("Keycloak profile apply failed: " + e.getMessage(), e);
        }

        // Audience wiring (see applyAudience for the backend vs SPA/NATIVE split).
        applyAudience(profile, realmName, slug, clientUuid, req.audience());

        App entity = new App(tenantId, slug, displayName, slug);
        entity.setProfile(profile.name());
        if (profile == AppProfile.NATIVE_PKCE) {
            entity.setIosTeamId(req.iosTeamId());
            entity.setIosBundleId(req.iosBundleId());
            entity.setAndroidPackage(req.androidPackage());
            entity.setAndroidCertSha256(req.androidCertSha256());
        }
        // Persist the requested audience so a startup reconcile can re-apply the
        // audience mappers after a realm rebuild.
        if (req.audience() != null && !req.audience().isEmpty()) {
            entity.setAudience(String.join(",", req.audience()));
        }
        App app = repo.save(entity);
        // Public clients (SPA_PKCE, NATIVE_PKCE) have no secret; KC returns null/empty.
        String secret = (profile == AppProfile.SPA_PKCE || profile == AppProfile.NATIVE_PKCE)
            ? null
            : keycloak.getClientSecret(realmName, clientUuid);

        audit.recordSuccess(SYSTEM_ACTOR, SYSTEM_KIND, tenantId,
            "app.create", "app", app.getId().toString(),
            Map.of("tenantSlug", tenant.getSlug(), "appSlug", slug,
                   "profile", profile.name()),
            Map.of("clientId", slug, "realm", realmName, "profile", profile.name()));

        return new AppCreationResult(app, secret);
    }

    /**
     * One-shot retry around the KC admin client's findClientUuid + createClient
     * pair. The admin client occasionally returns 403 right after auth-manager
     * pod restart or KC cluster rolling restart — the admin token's session-cached
     * realm info hasn't propagated yet. Empirically: a 1s sleep + retry succeeds.
     * After the second attempt, propagates the original exception.
     *
     * Returns the client UUID for an existing client (idempotent) or the newly-
     * created one. The internal find+create pattern is unchanged; only the
     * exception handling is wrapped.
     */
    private String findOrCreateClientWithRetry(String realmName, String slug, String displayName) {
        try {
            return keycloak.findClientUuid(realmName, slug)
                .orElseGet(() -> keycloak.createClient(realmName, slug, displayName));
        } catch (jakarta.ws.rs.ForbiddenException e1) {
            log.warn("KC admin client returned 403 for realm '{}' client '{}' — invalidating admin token + sleeping 1s + retrying once",
                realmName, slug);
            keycloak.invalidateAdminToken();
            try { Thread.sleep(1000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
            try {
                return keycloak.findClientUuid(realmName, slug)
                    .orElseGet(() -> keycloak.createClient(realmName, slug, displayName));
            } catch (jakarta.ws.rs.ForbiddenException e2) {
                log.error("KC admin client returned 403 on retry — admin token cache may be stuck; re-throwing");
                throw e2;
            }
        }
    }

    private void applyProfile(AppProfile profile, Tenant tenant, String slug, String clientUuid,
                              String iosBundleId) {
        String realmName = tenant.getRealmName();
        switch (profile) {
            case CONFIDENTIAL_BACKEND -> {
                // current behavior; KC's default state on createClient is already
                // confidential + serviceAccountsEnabled. Explicit no-op.
            }
            case SPA_PKCE -> {
                // 1. Flip to public + PKCE-S256
                keycloak.setClientPublic(realmName, slug, true);
                Map<String, String> attrs = new LinkedHashMap<>();
                attrs.put("pkce.code.challenge.method", "S256");
                attrs.put("client.use.lightweight.access.token.enabled", "false");
                keycloak.setClientAttributes(realmName, clientUuid, attrs);
                // 2. Redirect URIs + web origins from tenant's registered hostnames.
                //    Mirrors UsermanagementBootstrap.ensureStandardRedirectUris.
                List<String> hostnames = hostnameRepo.findByTenantId(tenant.getId()).stream()
                    .map(h -> h.getHostname())
                    .toList();
                String platformHost = kcProps.platform() == null ? null : kcProps.platform().host();
                keycloak.setStandardRedirectUris(realmName, clientUuid, hostnames, platformHost, false);
                // 3. Disable directGrants + serviceAccounts (SPA doesn't need either).
                //    setClientPublic above already cleared serviceAccountsEnabled, but
                //    set explicitly here too so the intent is auditable in one place.
                keycloak.setClientFlowFlags(realmName, clientUuid,
                    /* standardFlow */ true,
                    /* directGrants */ false,
                    /* serviceAccounts */ false);
            }
            case NATIVE_PKCE -> {
                // 1. Flip to public + PKCE-S256 (same hardening as SPA_PKCE).
                keycloak.setClientPublic(realmName, slug, true);
                Map<String, String> attrs = new LinkedHashMap<>();
                attrs.put("pkce.code.challenge.method", "S256");
                attrs.put("client.use.lightweight.access.token.enabled", "false");
                keycloak.setClientAttributes(realmName, clientUuid, attrs);
                // 2. Native redirect URIs: app-link https://<host>/auth/callback per
                //    tenant hostname + custom scheme <bundleId>://auth. No web origins.
                List<String> hostnames = hostnameRepo.findByTenantId(tenant.getId()).stream()
                    .map(h -> h.getHostname())
                    .toList();
                keycloak.setNativeRedirectUris(realmName, clientUuid, hostnames, iosBundleId);
                // 3. Disable directGrants + serviceAccounts (native uses auth-code + PKCE).
                keycloak.setClientFlowFlags(realmName, clientUuid,
                    /* standardFlow */ true,
                    /* directGrants */ false,
                    /* serviceAccounts */ false);
            }
            case SERVICE_ACCOUNT_ONLY -> {
                keycloak.setClientFlowFlags(realmName, clientUuid,
                    /* standardFlow */ false,
                    /* directGrants */ false,
                    /* serviceAccounts */ true);
                Map<String, String> attrs = new LinkedHashMap<>();
                attrs.put("client.use.lightweight.access.token.enabled", "false");
                keycloak.setClientAttributes(realmName, clientUuid, attrs);
            }
        }
    }

    /**
     * Wires token audience for a freshly-shaped client. Backend profiles
     * (CONFIDENTIAL_BACKEND / SERVICE_ACCOUNT_ONLY) get a per-backend
     * client_scope on {@code usermanagement} so BFF-minted tokens carry
     * {@code aud:<slug>} — the audience list is derived from the slug, not
     * {@code audience}. SPA_PKCE / NATIVE_PKCE mint tokens directly against
     * their own client, so each entry in {@code audience} becomes a self-aud
     * mapper on that client. Best-effort: mapper failures are logged, not fatal.
     */
    private void applyAudience(AppProfile profile, String realmName, String slug,
                               String clientUuid, List<String> audience) {
        if (profile == AppProfile.CONFIDENTIAL_BACKEND || profile == AppProfile.SERVICE_ACCOUNT_ONLY) {
            try {
                keycloak.ensureUsermanagementAudienceFor(realmName, slug);
            } catch (Exception e) {
                log.warn("Failed to ensure usermanagement audience for {}: {}", slug, e.getMessage());
                // Don't fail — operator can retry via UI / admin repair endpoint.
            }
        } else if (audience != null) {
            for (String aud : audience) {
                if (aud == null || aud.isBlank() || aud.equals(slug)) continue;
                try {
                    keycloak.ensureAudienceMapper(realmName, clientUuid, aud);
                } catch (Exception e) {
                    log.warn("Failed to create audience mapper '{}' on client {}: {}",
                        aud, slug, e.getMessage());
                }
            }
        }
    }

    /**
     * Recreates an app's Keycloak client from its persisted {@link App} row and
     * re-applies its stored profile shape + audience wiring. Shares the
     * {@link #findOrCreateClientWithRetry}, {@link #applyProfile} and
     * {@link #applyAudience} code paths with {@link #create}, so a reconciled
     * client lands in the exact same KC state as one created via the API.
     *
     * <p>Intended for the startup reconcile runner, which recovers app clients
     * lost to a realm rebuild. The caller is responsible for the
     * create-if-missing guard (only invoke this when the client is absent);
     * this method itself is idempotent (find-or-create) but will (re)shape the
     * client, so it must not be called against clients that should be left
     * untouched.
     *
     * <p>Rows with a null/blank or unrecognized {@code profile} are skipped
     * with a log line (nothing to reconstruct).
     */
    public void provisionClient(Tenant tenant, App app) {
        String stored = app.getProfile();
        if (stored == null || stored.isBlank()) {
            log.info("Skipping client reconcile for app '{}' in realm '{}': no stored profile",
                app.getSlug(), tenant.getRealmName());
            return;
        }
        AppProfile profile;
        try {
            profile = AppProfile.valueOf(stored);
        } catch (IllegalArgumentException e) {
            log.warn("Skipping client reconcile for app '{}': unrecognized stored profile '{}'",
                app.getSlug(), stored);
            return;
        }
        String realmName = tenant.getRealmName();
        String slug = app.getSlug();
        String clientUuid = findOrCreateClientWithRetry(realmName, slug, app.getDisplayName());
        applyProfile(profile, tenant, slug, clientUuid, app.getIosBundleId());
        applyAudience(profile, realmName, slug, clientUuid, parseAudience(app.getAudience()));
    }

    private static List<String> parseAudience(String csv) {
        if (csv == null || csv.isBlank()) return List.of();
        return java.util.Arrays.stream(csv.split(","))
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .toList();
    }

    @Transactional(readOnly = true)
    public List<App> listByTenant(UUID tenantId) {
        tenants.get(tenantId);  // 404 if tenant gone
        return repo.findByTenantIdOrderByCreatedAtDesc(tenantId);
    }

    /**
     * Inspects the KC client and returns its {@link AppProfile}. Mirrors the
     * detection logic in {@code OnboardingBundleService} — best-effort, with
     * {@link AppProfile#CONFIDENTIAL_BACKEND} as the safe default on lookup
     * failure. Exposed for the admin-repair endpoint that needs to filter to
     * backend-shaped apps.
     */
    /**
     * Profile for a persisted {@link App}: prefers the stored {@code profile}
     * column when present (so NATIVE_PKCE apps — which are shape-identical to
     * SPA_PKCE in KC — report correctly), falling back to KC-derivation for
     * legacy rows where {@code profile} is null.
     */
    @Transactional(readOnly = true)
    public AppProfile detectProfile(App app, String realmName) {
        String stored = app.getProfile();
        if (stored != null && !stored.isBlank()) {
            try {
                return AppProfile.valueOf(stored);
            } catch (IllegalArgumentException e) {
                log.warn("App {} has unrecognized stored profile '{}' — falling back to KC derivation",
                    app.getSlug(), stored);
            }
        }
        return detectProfile(realmName, app.getClientId());
    }

    @Transactional(readOnly = true)
    public AppProfile detectProfile(String realmName, String clientId) {
        try {
            var uuidOpt = keycloak.findClientUuid(realmName, clientId);
            if (uuidOpt.isEmpty()) return AppProfile.CONFIDENTIAL_BACKEND;
            var c = keycloak.findClientRepresentation(realmName, clientId);
            if (c == null) return AppProfile.CONFIDENTIAL_BACKEND;
            if (Boolean.TRUE.equals(c.isPublicClient())) return AppProfile.SPA_PKCE;
            boolean standard = !Boolean.FALSE.equals(c.isStandardFlowEnabled());
            boolean sa = Boolean.TRUE.equals(c.isServiceAccountsEnabled());
            if (!standard && sa) return AppProfile.SERVICE_ACCOUNT_ONLY;
            return AppProfile.CONFIDENTIAL_BACKEND;
        } catch (Exception e) {
            log.warn("detectProfile({}, {}) failed: {} — defaulting to CONFIDENTIAL_BACKEND",
                realmName, clientId, e.getMessage());
            return AppProfile.CONFIDENTIAL_BACKEND;
        }
    }

    @Transactional(readOnly = true)
    public App get(UUID tenantId, UUID appId) {
        return repo.findById(appId)
            .filter(a -> a.getTenantId().equals(tenantId))
            .orElseThrow(() -> new AppNotFoundException(appId.toString()));
    }

    public void delete(UUID tenantId, UUID appId, String actor) {
        Tenant tenant = tenants.get(tenantId);
        App app = get(tenantId, appId);

        try {
            keycloak.findClientUuid(tenant.getRealmName(), app.getClientId())
                .ifPresent(uuid -> keycloak.deleteClient(tenant.getRealmName(), uuid));
        } catch (Exception e) {
            log.error("Keycloak client delete failed for app {}; removing DB row anyway",
                      app.getSlug(), e);
        }
        repo.delete(app);

        audit.recordSuccess(SYSTEM_ACTOR, SYSTEM_KIND, tenantId,
            "app.delete", "app", appId.toString(),
            null,
            Map.of("tenantSlug", tenant.getSlug(), "appSlug", app.getSlug()));
    }

    /**
     * Current SA assignments on usermanagement for this app's service account.
     * Returns empty list when the app's client has no service account (e.g.,
     * SPA_PKCE) -- does NOT throw.
     */
    @Transactional(readOnly = true)
    public List<String> getServiceAccountPermissions(UUID tenantId, UUID appId) {
        App app = get(tenantId, appId);
        Tenant tenant = tenants.get(tenantId);
        String realmName = tenant.getRealmName();

        String appClientUuid = keycloak.findClientUuid(realmName, app.getClientId()).orElse(null);
        if (appClientUuid == null) return List.of();
        String saUserId = keycloak.findServiceAccountUserId(realmName, appClientUuid).orElse(null);
        if (saUserId == null) return List.of();

        return keycloak.getUserClientRoles(realmName, saUserId, UsermanagementBootstrap.CLIENT_SLUG)
            .stream().sorted().toList();
    }

    /**
     * Replaces the app's service-account user assignments on the
     * {@code usermanagement} client with the given set (additive + removal).
     * Each name must exist as a client role on {@code usermanagement} (atomic
     * perm); rejects with {@link IllegalArgumentException} if any doesn't
     * exist. Returns the effective list after the operation.
     *
     * <p>Fails with {@link IllegalStateException} if the app's client has
     * {@code serviceAccountsEnabled=false} (e.g. an SPA_PKCE client) -- there's
     * no service-account user to assign roles to.
     */
    public List<String> updateServiceAccountPermissions(
        UUID tenantId, UUID appId, Set<String> desired, String actor
    ) {
        App app = get(tenantId, appId);
        Tenant tenant = tenants.get(tenantId);
        String realmName = tenant.getRealmName();

        String appClientUuid = keycloak.findClientUuid(realmName, app.getClientId())
            .orElseThrow(() -> new IllegalStateException(
                "Keycloak client not found for app " + app.getSlug()));
        String umClientUuid = keycloak.findClientUuid(realmName, UsermanagementBootstrap.CLIENT_SLUG)
            .orElseThrow(() -> new IllegalStateException(
                "usermanagement client not found in realm " + realmName));
        String saUserId = keycloak.findServiceAccountUserId(realmName, appClientUuid)
            .orElseThrow(() -> new IllegalStateException(
                "App " + app.getSlug() + " has no service account user (serviceAccountsEnabled=false?)"));

        // Validate desired perms exist as client roles on usermanagement
        Set<String> validPerms = new HashSet<>(keycloak.listClientRoleNames(realmName, umClientUuid));
        Set<String> unknown = new HashSet<>(desired);
        unknown.removeAll(validPerms);
        if (!unknown.isEmpty()) {
            throw new IllegalArgumentException(
                "Unknown permissions on usermanagement client: " + unknown);
        }

        // Current direct assignments on usermanagement for the SA user
        Set<String> current = new HashSet<>(
            keycloak.getUserClientRoles(realmName, saUserId, UsermanagementBootstrap.CLIENT_SLUG));
        Set<String> toAdd = new HashSet<>(desired);
        toAdd.removeAll(current);
        Set<String> toRemove = new HashSet<>(current);
        toRemove.removeAll(desired);

        for (String p : toAdd) {
            keycloak.assignClientRoleToUser(realmName, saUserId, UsermanagementBootstrap.CLIENT_SLUG, p);
        }
        for (String p : toRemove) {
            keycloak.removeClientRoleFromUser(realmName, saUserId, UsermanagementBootstrap.CLIENT_SLUG, p);
        }

        audit.recordSuccess(actor, SYSTEM_KIND, tenantId,
            "app.service_account.permissions.update", "app", appId.toString(),
            Map.of("desired", desired),
            Map.of("added", toAdd, "removed", toRemove));

        return keycloak.getUserClientRoles(realmName, saUserId, UsermanagementBootstrap.CLIENT_SLUG)
            .stream().sorted().toList();
    }

    public record AppCreationResult(App app, String clientSecret) {}
}
