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
            clientUuid = keycloak.findClientUuid(realmName, slug)
                .orElseGet(() -> keycloak.createClient(realmName, slug, displayName));
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
            applyProfile(profile, tenant, slug, clientUuid);
        } catch (Exception e) {
            audit.recordFailure(SYSTEM_ACTOR, SYSTEM_KIND, tenantId,
                "app.create", "app", null,
                Map.of("tenantSlug", tenant.getSlug(), "appSlug", slug, "profile", profile.name()),
                e,
                Map.of("reason", "keycloak_profile_apply_failed"));
            throw new RuntimeException("Keycloak profile apply failed: " + e.getMessage(), e);
        }

        // Audience mappers: skip self + blanks + duplicates.
        if (req.audience() != null) {
            for (String aud : req.audience()) {
                if (aud == null || aud.isBlank() || aud.equals(slug)) continue;
                try {
                    keycloak.ensureAudienceMapper(realmName, clientUuid, aud);
                } catch (Exception e) {
                    log.warn("Failed to create audience mapper '{}' on client {}: {}",
                        aud, slug, e.getMessage());
                }
            }
        }

        App app = repo.save(new App(tenantId, slug, displayName, slug));
        // Public clients (SPA_PKCE) have no secret; KC returns null/empty.
        String secret = profile == AppProfile.SPA_PKCE
            ? null
            : keycloak.getClientSecret(realmName, clientUuid);

        audit.recordSuccess(SYSTEM_ACTOR, SYSTEM_KIND, tenantId,
            "app.create", "app", app.getId().toString(),
            Map.of("tenantSlug", tenant.getSlug(), "appSlug", slug,
                   "profile", profile.name()),
            Map.of("clientId", slug, "realm", realmName, "profile", profile.name()));

        return new AppCreationResult(app, secret);
    }

    private void applyProfile(AppProfile profile, Tenant tenant, String slug, String clientUuid) {
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

    @Transactional(readOnly = true)
    public List<App> listByTenant(UUID tenantId) {
        tenants.get(tenantId);  // 404 if tenant gone
        return repo.findByTenantIdOrderByCreatedAtDesc(tenantId);
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
