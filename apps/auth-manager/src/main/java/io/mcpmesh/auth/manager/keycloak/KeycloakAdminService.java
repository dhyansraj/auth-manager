package io.mcpmesh.auth.manager.keycloak;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientScopeResource;
import org.keycloak.admin.client.resource.ClientScopesResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.representations.idm.authorization.Logic;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.RolePolicyRepresentation;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.representations.info.ServerInfoRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Read-only Keycloak admin operations used by health checks and discovery.
 * Mutating operations (create realm, create client, etc.) get their own
 * services as Phase 1 progresses.
 */
@Service
public class KeycloakAdminService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakAdminService.class);

    private final Keycloak admin;

    public KeycloakAdminService(Keycloak admin) {
        this.admin = admin;
    }

    /** Round-trips to Keycloak; throws if the server is unreachable or the token is rejected. */
    public ServerInfoRepresentation serverInfo() {
        return admin.serverInfo().getInfo();
    }

    /**
     * Force the KC admin client to discard its cached bearer token. The next
     * admin REST call will re-authenticate from scratch (username/password
     * grant on master realm's admin-cli), producing a fresh token whose
     * realm-role view INCLUDES any realms created after the previous token
     * was issued.
     *
     * Use after creating a new realm so the immediate subsequent bootstrap
     * call (UsermanagementBootstrap) doesn't 403 on the new realm.
     */
    public void invalidateAdminToken() {
        try {
            var tm = admin.tokenManager();
            String current = tm.getAccessTokenString();
            if (current != null) {
                tm.invalidate(current);
            }
            log.debug("KC admin token invalidated; next call will re-authenticate");
        } catch (Exception e) {
            log.warn("Failed to invalidate KC admin token: {}", e.getMessage());
        }
    }

    /** List of realms this admin can see; small per deployment, no pagination needed. */
    public List<RealmRepresentation> listRealms() {
        return admin.realms().findAll();
    }

    /**
     * Checks whether a realm with the given name exists. Uses the admin
     * "get realm" endpoint and treats a 404 as "does not exist". Any other
     * failure propagates.
     */
    public boolean realmExists(String realmName) {
        try {
            admin.realm(realmName).toRepresentation();
            return true;
        } catch (NotFoundException e) {
            return false;
        }
    }

    /**
     * Creates a Keycloak realm with the platform's standard defaults (no
     * self-registration, brute-force protection on, SSL required for
     * external traffic, conservative session lifetimes). Throws if the
     * realm already exists -- callers that want idempotency should check
     * {@link #realmExists(String)} first.
     *
     * <p>Returns the realm name on success so callers can confirm what
     * was created.
     */
    public String createRealm(String realmName, String displayName) {
        RealmRepresentation realm = new RealmRepresentation();
        realm.setRealm(realmName);
        realm.setDisplayName(displayName);
        realm.setEnabled(true);
        realm.setSslRequired("external");
        realm.setRegistrationAllowed(false);
        realm.setLoginWithEmailAllowed(true);
        realm.setDuplicateEmailsAllowed(false);
        realm.setResetPasswordAllowed(true);
        realm.setEditUsernameAllowed(false);
        realm.setBruteForceProtected(true);
        realm.setAccessTokenLifespan(300);
        realm.setSsoSessionIdleTimeout(1800);
        realm.setSsoSessionMaxLifespan(36000);

        // SMTP config so the realm can send password-reset / verify-email actions.
        // In dev this points at MailHog; in prod, override via property (TODO).
        realm.setSmtpServer(java.util.Map.of(
            "host", "host.docker.internal",
            "port", "1025",
            "from", "noreply@" + realmName + ".local",
            "auth", "false",
            "ssl", "false",
            "starttls", "false"
        ));

        admin.realms().create(realm);
        return realmName;
    }

    /**
     * Idempotently sets the realm's {@code enabled} flag. Returns {@code true}
     * if the flag was changed (and the PUT issued); {@code false} if the realm
     * was already in the requested state (no round-trip).
     *
     * <p>Used by tenant soft-delete to disable the realm without destroying
     * users/clients/theme, and by tenant resurrect to re-enable it.
     */
    public boolean setRealmEnabled(String realmName, boolean enabled) {
        RealmRepresentation r = admin.realm(realmName).toRepresentation();
        if (r.isEnabled() != null && r.isEnabled() == enabled) {
            return false;
        }
        r.setEnabled(enabled);
        admin.realm(realmName).update(r);
        log.info("Realm '{}' enabled={}", realmName, enabled);
        return true;
    }

    /**
     * Permanently deletes the realm. Idempotent: a {@link NotFoundException}
     * from KC (realm already absent) is logged and swallowed so callers can
     * safely re-invoke during force-delete recovery.
     */
    public void deleteRealm(String realmName) {
        try {
            admin.realm(realmName).remove();
            log.info("Realm '{}' deleted from KC", realmName);
        } catch (NotFoundException e) {
            log.info("Realm '{}' already absent in KC (idempotent delete)", realmName);
        }
    }

    /**
     * Creates a confidential OIDC client in the given realm with platform defaults.
     * Returns the client UUID (Keycloak's internal id, not the clientId).
     */
    public String createClient(String realmName, String clientId, String displayName) {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(clientId);
        client.setName(displayName);
        client.setProtocol("openid-connect");
        client.setPublicClient(false);
        client.setClientAuthenticatorType("client-secret");
        client.setStandardFlowEnabled(true);
        client.setDirectAccessGrantsEnabled(true);
        client.setServiceAccountsEnabled(true);
        client.setFullScopeAllowed(true);
        client.setRedirectUris(java.util.List.of("*"));
        client.setWebOrigins(java.util.List.of("+"));

        try (Response response = admin.realm(realmName).clients().create(client)) {
            if (response.getStatus() < 200 || response.getStatus() >= 300) {
                throw new RuntimeException(
                    "Keycloak client create failed: HTTP " + response.getStatus()
                    + " " + response.getStatusInfo().getReasonPhrase());
            }
            // The Location header looks like .../clients/<uuid>
            String location = response.getHeaderString("Location");
            if (location == null) {
                throw new RuntimeException("Keycloak client create returned no Location header");
            }
            return location.substring(location.lastIndexOf('/') + 1);
        }
    }

    /** Fetches the client secret for a confidential client. */
    public String getClientSecret(String realmName, String clientUuid) {
        return admin.realm(realmName).clients().get(clientUuid).getSecret().getValue();
    }

    /**
     * Creates a public OIDC client suitable for browser/PKCE flows (no
     * client_secret, no service account, no direct access grants). Returns
     * the KC internal client UUID.
     *
     * <p>Used by {@code PlatformRoleBootstrap} to materialise the dev realm's
     * {@code usermanagement} client on fresh deployments without operators
     * having to click through the admin console. Callers are expected to
     * follow up with {@link #setStandardRedirectUris} and
     * {@link #setClientAttributes} to install the canonical config.
     */
    public String createPublicClient(String realmName, String clientId, String displayName) {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(clientId);
        client.setName(displayName);
        client.setProtocol("openid-connect");
        client.setPublicClient(true);
        client.setStandardFlowEnabled(true);
        client.setDirectAccessGrantsEnabled(false);
        client.setServiceAccountsEnabled(false);
        client.setFullScopeAllowed(true);
        client.setRedirectUris(java.util.List.of());
        client.setWebOrigins(java.util.List.of());

        try (Response response = admin.realm(realmName).clients().create(client)) {
            if (response.getStatus() < 200 || response.getStatus() >= 300) {
                throw new RuntimeException(
                    "Keycloak public client create failed: HTTP " + response.getStatus()
                    + " " + response.getStatusInfo().getReasonPhrase());
            }
            String location = response.getHeaderString("Location");
            if (location == null) {
                throw new RuntimeException("Keycloak public client create returned no Location header");
            }
            return location.substring(location.lastIndexOf('/') + 1);
        }
    }

    /**
     * Merges the given {@code attributes} into the client's existing
     * {@code attributes} map. Existing keys not in the input are preserved;
     * keys present in the input are overwritten. Idempotent: re-running with
     * the same values is a silent no-op (the update still round-trips but KC
     * state is unchanged).
     *
     * <p>Used to install KC client-level toggles that don't have first-class
     * setters on {@link ClientRepresentation} (e.g.
     * {@code backchannel.logout.url}, {@code pkce.code.challenge.method},
     * {@code client.use.lightweight.access.token.enabled}).
     */
    public void setClientAttributes(String realmName, String clientUuid,
                                    java.util.Map<String, String> attributes) {
        if (attributes == null || attributes.isEmpty()) return;
        ClientResource clientResource = admin.realm(realmName).clients().get(clientUuid);
        ClientRepresentation rep = clientResource.toRepresentation();
        java.util.Map<String, String> attrs = rep.getAttributes();
        if (attrs == null) {
            attrs = new java.util.HashMap<>();
        }
        attrs.putAll(attributes);
        rep.setAttributes(attrs);
        clientResource.update(rep);
    }

    /**
     * Fetches a client's current state, applies {@code mutator}, and PUTs the
     * result back to KC in a single round-trip. Returns {@code true} if the
     * mutator reported a change (and the update was issued); {@code false} if
     * the mutator reported no-op (and we skipped the PUT entirely).
     *
     * <p>Use when a caller needs to patch multiple fields on the same client
     * atomically (e.g. attributes + webOrigins) without paying for two
     * toRepresentation/update cycles.
     */
    public boolean mutateClient(String realmName, String clientUuid,
                                java.util.function.Predicate<ClientRepresentation> mutator) {
        ClientResource clientResource = admin.realm(realmName).clients().get(clientUuid);
        ClientRepresentation rep = clientResource.toRepresentation();
        if (!mutator.test(rep)) return false;
        clientResource.update(rep);
        return true;
    }

    /**
     * Replaces a client's {@code redirectUris} and {@code webOrigins} with the
     * canonical set for the {@code usermanagement} client on a realm:
     *
     * <ul>
     *   <li>{@code https://<host>/admin/*} — admin-ui at every tenant host
     *       (and platform host)</li>
     *   <li>{@code https://<host>/_bff/callback} — BFF callback at every
     *       tenant host (and platform host)</li>
     *   <li>{@code http://localhost:5173/admin/*} — local dev (Vite)</li>
     * </ul>
     *
     * <p>The {@code dev} (platform) realm gets only the platform host +
     * localhost variants ({@code tenantHostnames} is ignored if
     * {@code isDevRealm} is true, since dev has no tenant hosts).
     *
     * <p>The {@code webOrigins} list is the origin (scheme://host) for each
     * trusted host so CORS preflight requests succeed; KC also accepts {@code
     * "+"} to mean "all redirect-URI origins", but we list them explicitly so
     * the wildcard intent is auditable.
     *
     * <p>Idempotent: the new lists overwrite whatever was there. Same input
     * always produces the same KC state, intentionally so backfill runs can
     * repair drift introduced by ad-hoc kcadm scripts.
     */
    public void setStandardRedirectUris(String realmName, String clientUuid,
                                        List<String> tenantHostnames,
                                        String platformHost, boolean isDevRealm) {
        Set<String> redirectUris = new java.util.LinkedHashSet<>();
        Set<String> webOrigins   = new java.util.LinkedHashSet<>();

        // Platform host -- present in BOTH dev and tenant realms so an admin
        // signed in via auth.<host> can land back on the platform admin-ui.
        if (platformHost != null && !platformHost.isBlank()) {
            redirectUris.add("https://" + platformHost + "/admin/*");
            redirectUris.add("https://" + platformHost + "/_bff/callback");
            webOrigins.add("https://" + platformHost);
        }

        // Per-tenant hosts -- only on tenant realms; dev has none.
        if (!isDevRealm && tenantHostnames != null) {
            for (String h : tenantHostnames) {
                if (h == null || h.isBlank()) continue;
                redirectUris.add("https://" + h + "/admin/*");
                redirectUris.add("https://" + h + "/_bff/callback");
                webOrigins.add("https://" + h);
            }
        }

        // Local Vite dev server -- on every realm so devs can hit any tenant
        // from their laptop without per-realm KC config drift.
        redirectUris.add("http://localhost:5173/admin/*");
        webOrigins.add("http://localhost:5173");

        ClientResource clientResource = admin.realm(realmName).clients().get(clientUuid);
        ClientRepresentation rep = clientResource.toRepresentation();
        rep.setRedirectUris(new java.util.ArrayList<>(redirectUris));
        rep.setWebOrigins(new java.util.ArrayList<>(webOrigins));
        clientResource.update(rep);
        log.info("setStandardRedirectUris: realm '{}' client {} now trusts {} redirect URIs / {} web origins",
            realmName, clientUuid, redirectUris.size(), webOrigins.size());
    }

    /**
     * Switches a client between confidential and public. For public, the
     * client_secret is removed and clientAuthenticatorType is cleared. Use
     * for UI / SPA clients that should use PKCE flow.
     */
    public void setClientPublic(String realmName, String clientId, boolean publicClient) {
        String clientUuid = findClientUuid(realmName, clientId)
            .orElseThrow(() -> new IllegalStateException("Client not found: " + clientId));
        ClientResource clientResource = admin.realm(realmName).clients().get(clientUuid);
        ClientRepresentation rep = clientResource.toRepresentation();
        rep.setPublicClient(publicClient);
        if (publicClient) {
            rep.setSecret(null);
            rep.setClientAuthenticatorType(null);
            // Public clients can't have service accounts -- clear that.
            rep.setServiceAccountsEnabled(false);
        }
        clientResource.update(rep);
    }

    /** Checks if a client with the given clientId exists in the realm. */
    public boolean clientExists(String realmName, String clientId) {
        return !admin.realm(realmName).clients().findByClientId(clientId).isEmpty();
    }

    /** Deletes the client identified by its KC UUID. */
    public void deleteClient(String realmName, String clientUuid) {
        admin.realm(realmName).clients().get(clientUuid).remove();
    }

    /** Finds a client by its clientId, returns its KC UUID. */
    public java.util.Optional<String> findClientUuid(String realmName, String clientId) {
        var matches = admin.realm(realmName).clients().findByClientId(clientId);
        return matches.isEmpty() ? java.util.Optional.empty() : java.util.Optional.of(matches.get(0).getId());
    }

    /**
     * Returns the full {@link ClientRepresentation} for a clientId, or
     * {@code null} if no such client exists. Convenience for callers that need
     * to inspect flag state (publicClient, standardFlowEnabled, etc.) without
     * also paying for a separate {@code findClientUuid} round-trip.
     */
    public ClientRepresentation findClientRepresentation(String realmName, String clientId) {
        var matches = admin.realm(realmName).clients().findByClientId(clientId);
        return matches.isEmpty() ? null : matches.get(0);
    }

    /**
     * Sets the three top-level OAuth2 flow flags on a client (standardFlow,
     * directGrants, serviceAccounts). Used by app-creation profiles to flip a
     * freshly-created client into the right shape (SPA / service-account-only)
     * without needing a separate kcadm script. Idempotent.
     */
    public void setClientFlowFlags(String realmName, String clientUuid,
                                   boolean standardFlow,
                                   boolean directGrants,
                                   boolean serviceAccounts) {
        ClientResource clientResource = admin.realm(realmName).clients().get(clientUuid);
        ClientRepresentation rep = clientResource.toRepresentation();
        rep.setStandardFlowEnabled(standardFlow);
        rep.setDirectAccessGrantsEnabled(directGrants);
        rep.setServiceAccountsEnabled(serviceAccounts);
        clientResource.update(rep);
    }

    /**
     * Idempotently ensures an oidc-audience-mapper on the given client, adding
     * the named audience client to access_token's "aud" claim.
     * Returns true if a mapper was newly created; false if it already existed.
     */
    public boolean ensureAudienceMapper(String realmName, String clientUuid, String audience) {
        ClientResource clientRes = admin.realm(realmName).clients().get(clientUuid);
        String mapperName = "audience-" + audience;
        var existing = clientRes.getProtocolMappers().getMappersPerProtocol("openid-connect");
        if (existing != null) {
            for (ProtocolMapperRepresentation m : existing) {
                if (mapperName.equals(m.getName())
                    && "oidc-audience-mapper".equals(m.getProtocolMapper())
                    && m.getConfig() != null
                    && audience.equals(m.getConfig().get("included.client.audience"))) {
                    return false;
                }
            }
        }
        ProtocolMapperRepresentation rep = new ProtocolMapperRepresentation();
        rep.setName(mapperName);
        rep.setProtocol("openid-connect");
        rep.setProtocolMapper("oidc-audience-mapper");
        java.util.Map<String, String> cfg = new java.util.LinkedHashMap<>();
        cfg.put("included.client.audience", audience);
        cfg.put("id.token.claim", "false");
        cfg.put("access.token.claim", "true");
        rep.setConfig(cfg);
        try (Response resp = clientRes.getProtocolMappers().createMapper(rep)) {
            if (resp.getStatus() >= 300) {
                log.warn("ensureAudienceMapper({}, {}, {}) failed: HTTP {}",
                    realmName, clientUuid, audience, resp.getStatus());
                return false;
            }
        }
        log.info("ensureAudienceMapper: added '{}' on client {} in realm '{}'",
            mapperName, clientUuid, realmName);
        return true;
    }

    /**
     * Idempotently configures KC so BFF-issued tokens (minted via the realm's
     * {@code usermanagement} client) carry {@code aud:<audienceClientId>}.
     *
     * <p>Implementation:
     * <ol>
     *   <li>Find or create a client_scope named {@code audience-<audienceClientId>}
     *       with {@code includeInTokenScope=false}.</li>
     *   <li>Find or create an {@code oidc-audience-mapper} on that scope with
     *       {@code included.client.audience=<audienceClientId>},
     *       {@code access.token.claim=true},
     *       {@code id.token.claim=false}.</li>
     *   <li>Add the scope to {@code usermanagement}'s default-client-scopes.</li>
     * </ol>
     *
     * <p>Safe to call repeatedly. Logs at info on first creation, debug on no-op.
     *
     * <p>Replaces the legacy {@link #ensureAudienceMapper} pattern for backend
     * profiles — that one installed the mapper on the backend client itself,
     * which doesn't fire when tokens flow through the BFF's {@code usermanagement}
     * client.
     */
    public void ensureUsermanagementAudienceFor(String realmName, String audienceClientId) {
        if (audienceClientId == null || audienceClientId.isBlank()) {
            throw new IllegalArgumentException("audienceClientId must be non-blank");
        }
        String scopeName = "audience-" + audienceClientId;
        RealmResource realm = admin.realm(realmName);
        ClientScopesResource scopes = realm.clientScopes();

        // 1. Find or create the client scope.
        String scopeId = findClientScopeId(scopes, scopeName);
        if (scopeId == null) {
            ClientScopeRepresentation csr = new ClientScopeRepresentation();
            csr.setName(scopeName);
            csr.setProtocol("openid-connect");
            csr.setDescription("Adds aud:" + audienceClientId + " to access tokens minted via the BFF's usermanagement client.");
            java.util.Map<String, String> scopeAttrs = new java.util.LinkedHashMap<>();
            scopeAttrs.put("include.in.token.scope", "false");
            scopeAttrs.put("display.on.consent.screen", "false");
            csr.setAttributes(scopeAttrs);
            try (Response resp = scopes.create(csr)) {
                if (resp.getStatus() < 200 || resp.getStatus() >= 300) {
                    throw new RuntimeException(
                        "Create client_scope " + scopeName + " failed: HTTP " + resp.getStatus()
                        + " " + resp.getStatusInfo().getReasonPhrase());
                }
            }
            scopeId = findClientScopeId(scopes, scopeName);
            if (scopeId == null) {
                throw new IllegalStateException(
                    "Client scope " + scopeName + " not found after create in realm " + realmName);
            }
            log.info("ensureUsermanagementAudienceFor: created client_scope '{}' in realm '{}'",
                scopeName, realmName);
        } else {
            log.debug("ensureUsermanagementAudienceFor: client_scope '{}' already exists in realm '{}'",
                scopeName, realmName);
        }

        // 2. Find or create the oidc-audience-mapper on the scope.
        ClientScopeResource scopeRes = scopes.get(scopeId);
        String mapperName = "audience-mapper-" + audienceClientId;
        boolean mapperPresent = false;
        var existingMappers = scopeRes.getProtocolMappers().getMappersPerProtocol("openid-connect");
        if (existingMappers != null) {
            for (ProtocolMapperRepresentation m : existingMappers) {
                if ("oidc-audience-mapper".equals(m.getProtocolMapper())
                    && m.getConfig() != null
                    && audienceClientId.equals(m.getConfig().get("included.client.audience"))) {
                    mapperPresent = true;
                    break;
                }
            }
        }
        if (!mapperPresent) {
            ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
            mapper.setName(mapperName);
            mapper.setProtocol("openid-connect");
            mapper.setProtocolMapper("oidc-audience-mapper");
            java.util.Map<String, String> cfg = new java.util.LinkedHashMap<>();
            cfg.put("included.client.audience", audienceClientId);
            cfg.put("id.token.claim", "false");
            cfg.put("access.token.claim", "true");
            mapper.setConfig(cfg);
            try (Response resp = scopeRes.getProtocolMappers().createMapper(mapper)) {
                if (resp.getStatus() < 200 || resp.getStatus() >= 300) {
                    throw new RuntimeException(
                        "Create audience mapper on scope " + scopeName + " failed: HTTP " + resp.getStatus()
                        + " " + resp.getStatusInfo().getReasonPhrase());
                }
            }
            log.info("ensureUsermanagementAudienceFor: added oidc-audience-mapper on scope '{}' in realm '{}'",
                scopeName, realmName);
        } else {
            log.debug("ensureUsermanagementAudienceFor: oidc-audience-mapper already present on scope '{}' in realm '{}'",
                scopeName, realmName);
        }

        // 3. Add the scope to usermanagement's default-client-scopes.
        var umClientUuidOpt = findClientUuid(realmName, "usermanagement");
        if (umClientUuidOpt.isEmpty()) {
            throw new IllegalStateException(
                "usermanagement client not found in realm " + realmName
                + " — cannot wire BFF audience for " + audienceClientId);
        }
        ClientResource umRes = realm.clients().get(umClientUuidOpt.get());
        boolean alreadyDefault = false;
        try {
            var defaults = umRes.getDefaultClientScopes();
            if (defaults != null) {
                for (ClientScopeRepresentation d : defaults) {
                    if (scopeName.equals(d.getName())) {
                        alreadyDefault = true;
                        break;
                    }
                }
            }
        } catch (Exception e) {
            log.warn("ensureUsermanagementAudienceFor: getDefaultClientScopes failed in realm '{}': {}",
                realmName, e.getMessage());
        }
        if (!alreadyDefault) {
            umRes.addDefaultClientScope(scopeId);
            log.info("ensureUsermanagementAudienceFor: added scope '{}' to usermanagement's default-client-scopes in realm '{}'",
                scopeName, realmName);
        } else {
            log.debug("ensureUsermanagementAudienceFor: scope '{}' already in usermanagement's default-client-scopes in realm '{}'",
                scopeName, realmName);
        }
    }

    /**
     * Non-mutating check: returns true if {@code usermanagement}'s
     * default-client-scopes in the given realm includes
     * {@code audience-<audienceClientId>}. Best-effort — returns {@code true}
     * on any lookup failure so the bundle README doesn't emit a spurious
     * "missing audience" warning when the issue is really KC connectivity.
     */
    public boolean hasUsermanagementAudienceFor(String realmName, String audienceClientId) {
        String scopeName = "audience-" + audienceClientId;
        try {
            var umClientUuidOpt = findClientUuid(realmName, "usermanagement");
            if (umClientUuidOpt.isEmpty()) return true;
            ClientResource umRes = admin.realm(realmName).clients().get(umClientUuidOpt.get());
            var defaults = umRes.getDefaultClientScopes();
            if (defaults == null) return false;
            for (ClientScopeRepresentation d : defaults) {
                if (scopeName.equals(d.getName())) return true;
            }
            return false;
        } catch (Exception e) {
            log.debug("hasUsermanagementAudienceFor({}, {}) failed: {}",
                realmName, audienceClientId, e.getMessage());
            return true;
        }
    }

    private static String findClientScopeId(ClientScopesResource scopes, String name) {
        try {
            var all = scopes.findAll();
            if (all == null) return null;
            for (ClientScopeRepresentation cs : all) {
                if (name.equals(cs.getName())) return cs.getId();
            }
        } catch (Exception e) {
            // findAll may throw on transient KC issues; let caller treat as "missing".
        }
        return null;
    }

    /** Returns the service-account user UUID for the given client, or empty if serviceAccountsEnabled is false. */
    public java.util.Optional<String> findServiceAccountUserId(String realmName, String clientUuid) {
        try {
            var user = admin.realm(realmName).clients().get(clientUuid).getServiceAccountUser();
            return user == null ? java.util.Optional.empty() : java.util.Optional.of(user.getId());
        } catch (Exception e) {
            log.debug("findServiceAccountUserId({}, {}): {}", realmName, clientUuid, e.getMessage());
            return java.util.Optional.empty();
        }
    }

    /** Returns the names of every client role defined on the given client. */
    public List<String> listClientRoleNames(String realmName, String clientUuid) {
        try {
            return admin.realm(realmName).clients().get(clientUuid).roles().list()
                .stream().map(RoleRepresentation::getName).toList();
        } catch (Exception e) {
            log.warn("listClientRoleNames({}, {}) failed: {}", realmName, clientUuid, e.getMessage());
            return List.of();
        }
    }

    // -----------------------------------------------------------------------
    // Authorization model mutations (client-scoped, idempotent).
    //
    // All methods below check existence first and skip if the target already
    // exists. This lets ManifestService re-apply after a partial failure
    // without erroring on already-created resources.
    // -----------------------------------------------------------------------

    /**
     * Enables Authorization Services on the client (no-op if already enabled).
     *
     * <p>Resource-server decisionStrategy is AFFIRMATIVE so role-inclusion
     * semantics work (ADMIN-only user is allowed on ORDER:VIEW even though
     * VIEWER also has a permission for ORDER:VIEW).
     */
    public void enableAuthz(String realmName, String clientUuid) {
        ClientResource clientResource = admin.realm(realmName).clients().get(clientUuid);
        ClientRepresentation rep = clientResource.toRepresentation();
        if (!Boolean.TRUE.equals(rep.getAuthorizationServicesEnabled())) {
            rep.setAuthorizationServicesEnabled(Boolean.TRUE);
            // Confidential clients are required for authz services.
            rep.setServiceAccountsEnabled(Boolean.TRUE);
            rep.setPublicClient(Boolean.FALSE);
            clientResource.update(rep);
        }

        // Assert decisionStrategy unconditionally so re-runs (and legacy
        // realms created before this setting was applied) get repaired.
        AuthorizationResource authz = clientResource.authorization();
        var settings = authz.getSettings();
        if (settings.getDecisionStrategy() != DecisionStrategy.AFFIRMATIVE) {
            settings.setDecisionStrategy(DecisionStrategy.AFFIRMATIVE);
            authz.update(settings);
        }
    }

    /** Creates a client-scoped role; no-op if one already exists with that name. */
    public void createClientRole(String realmName, String clientUuid, String roleName) {
        ClientResource clientResource = admin.realm(realmName).clients().get(clientUuid);
        try {
            clientResource.roles().get(roleName).toRepresentation();
            return; // already exists
        } catch (NotFoundException ignored) {
            // create below
        }
        RoleRepresentation role = new RoleRepresentation();
        role.setName(roleName);
        clientResource.roles().create(role);
    }

    /**
     * Ensures a client role on the given client is a composite that includes
     * each of {@code childRoleNames} (also client roles on the same client).
     * Diff-based: only the missing children are added. Idempotent re-runs
     * are silent no-ops.
     *
     * <p>If the parent role doesn't exist, throws {@link IllegalStateException}
     * -- callers should have created it first via {@link #createClientRole}.
     * Missing children are logged + skipped (best-effort) so a single bad
     * name doesn't poison the whole bundle.
     *
     * <p>Used by the platform-permission bootstrap to wire
     * {@code tenant-admin} / {@code tenant-user-manager} as composites of the
     * atomic permission client roles defined by
     * {@code PlatformPermissions}.
     *
     * @return the number of newly-added composite memberships (0 if all
     *         already present)
     */
    public int ensureClientRoleComposites(String realmName, String clientUuid,
                                          String parentRoleName,
                                          List<String> childRoleNames) {
        ClientResource clientResource = admin.realm(realmName).clients().get(clientUuid);
        RoleResource parentResource;
        try {
            parentResource = clientResource.roles().get(parentRoleName);
            parentResource.toRepresentation();  // throws NotFoundException if missing
        } catch (NotFoundException e) {
            throw new IllegalStateException(
                "ensureClientRoleComposites: parent client role '" + parentRoleName
                + "' missing on client " + clientUuid + " in realm " + realmName);
        }

        // Snapshot existing composites; key by (containerId, name) so we only
        // count same-client matches as duplicates.
        Set<String> existingKeys = new HashSet<>();
        try {
            Set<RoleRepresentation> existing = parentResource.getRoleComposites();
            if (existing != null) {
                for (RoleRepresentation r : existing) {
                    if (Boolean.TRUE.equals(r.getClientRole())
                        && clientUuid.equals(r.getContainerId())) {
                        existingKeys.add(r.getName());
                    }
                }
            }
        } catch (Exception e) {
            log.warn("ensureClientRoleComposites: failed to list composites of '{}' on client {} in realm '{}': {}",
                parentRoleName, clientUuid, realmName, e.getMessage());
            return 0;
        }

        List<RoleRepresentation> toAdd = new java.util.ArrayList<>();
        for (String child : childRoleNames) {
            if (existingKeys.contains(child)) continue;
            try {
                RoleRepresentation childRep = clientResource.roles().get(child).toRepresentation();
                toAdd.add(childRep);
            } catch (NotFoundException e) {
                log.warn("ensureClientRoleComposites: child role '{}' missing on client {} in realm '{}' — skipping",
                    child, clientUuid, realmName);
            }
        }
        if (toAdd.isEmpty()) {
            log.debug("ensureClientRoleComposites: '{}' on client {} in realm '{}' already has all {} children",
                parentRoleName, clientUuid, realmName, childRoleNames.size());
            return 0;
        }
        parentResource.addComposites(toAdd);
        log.info("ensureClientRoleComposites: added {} children to '{}' on client {} in realm '{}'",
            toAdd.size(), parentRoleName, clientUuid, realmName);
        return toAdd.size();
    }

    /**
     * Ensures a realm role is a composite that includes each of the given
     * client roles on {@code clientUuid}. Diff-based: only the missing
     * children are added. Idempotent re-runs are no-ops.
     *
     * <p>Used by the platform-admin bootstrap to wire the cross-tenant
     * realm role to include all platform-level + tenant-level atomic
     * permissions defined on the dev realm's {@code usermanagement} client.
     *
     * <p>If the realm role doesn't exist, throws {@link IllegalStateException}.
     * Missing children are logged + skipped.
     *
     * @return the number of newly-added composite memberships (0 if all
     *         already present)
     */
    public int ensureRealmRoleClientComposites(String realmName, String realmRoleName,
                                                String clientUuid,
                                                List<String> childRoleNames) {
        RealmResource realm = admin.realm(realmName);
        RoleResource realmRoleResource;
        try {
            realmRoleResource = realm.roles().get(realmRoleName);
            realmRoleResource.toRepresentation();
        } catch (NotFoundException e) {
            throw new IllegalStateException(
                "ensureRealmRoleClientComposites: realm role '" + realmRoleName
                + "' missing in realm " + realmName);
        }

        Set<String> existingKeys = new HashSet<>();
        try {
            Set<RoleRepresentation> existing = realmRoleResource.getRoleComposites();
            if (existing != null) {
                for (RoleRepresentation r : existing) {
                    if (Boolean.TRUE.equals(r.getClientRole())
                        && clientUuid.equals(r.getContainerId())) {
                        existingKeys.add(r.getName());
                    }
                }
            }
        } catch (Exception e) {
            log.warn("ensureRealmRoleClientComposites: failed to list composites of realm role '{}' in realm '{}': {}",
                realmRoleName, realmName, e.getMessage());
            return 0;
        }

        ClientResource clientResource = realm.clients().get(clientUuid);
        List<RoleRepresentation> toAdd = new java.util.ArrayList<>();
        for (String child : childRoleNames) {
            if (existingKeys.contains(child)) continue;
            try {
                RoleRepresentation childRep = clientResource.roles().get(child).toRepresentation();
                toAdd.add(childRep);
            } catch (NotFoundException e) {
                log.warn("ensureRealmRoleClientComposites: child client role '{}' missing on client {} in realm '{}' — skipping",
                    child, clientUuid, realmName);
            }
        }
        if (toAdd.isEmpty()) {
            log.debug("ensureRealmRoleClientComposites: realm role '{}' in '{}' already has all {} children",
                realmRoleName, realmName, childRoleNames.size());
            return 0;
        }
        realmRoleResource.addComposites(toAdd);
        // KC requires the parent realm role to be flagged composite=true; set it
        // if it wasn't already (cheap idempotent re-set).
        try {
            RoleRepresentation parentRep = realmRoleResource.toRepresentation();
            if (!Boolean.TRUE.equals(parentRep.isComposite())) {
                parentRep.setComposite(true);
                realmRoleResource.update(parentRep);
            }
        } catch (Exception e) {
            log.warn("ensureRealmRoleClientComposites: failed to flag '{}' composite=true in '{}': {}",
                realmRoleName, realmName, e.getMessage());
        }
        log.info("ensureRealmRoleClientComposites: added {} children to realm role '{}' in '{}'",
            toAdd.size(), realmRoleName, realmName);
        return toAdd.size();
    }

    /**
     * Adds a client role as a composite of the realm's built-in
     * {@code default-roles-<realm>} role. KC auto-assigns this default role to
     * every user it creates (including users provisioned by the
     * "First Broker Login" flow for social IdPs), so adding {@code user-viewer}
     * here transparently grants it to every brokered user without our code
     * having to participate in the broker flow.
     *
     * <p>Idempotent: if the role is already a composite, this is a no-op.
     * Defensive: if the realm has no client with {@code clientId}, logs WARN
     * and returns without throwing.
     *
     * @return {@code true} if the role was newly added; {@code false} if it
     *         was already present, missing client, or any other skip.
     */
    public boolean ensureClientRoleInDefaultRoles(String realmName, String clientId, String roleName) {
        var clientUuidOpt = findClientUuid(realmName, clientId);
        if (clientUuidOpt.isEmpty()) {
            log.warn("ensureClientRoleInDefaultRoles: client '{}' not found in realm '{}' — skipping",
                clientId, realmName);
            return false;
        }
        String clientUuid = clientUuidOpt.get();

        RoleRepresentation clientRole;
        try {
            clientRole = admin.realm(realmName).clients().get(clientUuid)
                .roles().get(roleName).toRepresentation();
        } catch (NotFoundException e) {
            log.warn("ensureClientRoleInDefaultRoles: client role '{}:{}' not found in realm '{}' — skipping",
                clientId, roleName, realmName);
            return false;
        }

        String defaultRoleName = "default-roles-" + realmName;
        RoleResource defaultRole;
        try {
            defaultRole = admin.realm(realmName).roles().get(defaultRoleName);
            defaultRole.toRepresentation();  // throws NotFoundException if missing
        } catch (NotFoundException e) {
            log.warn("ensureClientRoleInDefaultRoles: '{}' not found in realm '{}' — skipping",
                defaultRoleName, realmName);
            return false;
        }

        List<RoleRepresentation> existing;
        try {
            var composites = defaultRole.getRoleComposites();
            existing = composites == null ? List.of() : List.copyOf(composites);
        } catch (Exception e) {
            log.warn("ensureClientRoleInDefaultRoles: failed to list composites of '{}' in realm '{}': {}",
                defaultRoleName, realmName, e.getMessage());
            return false;
        }
        boolean alreadyPresent = existing.stream().anyMatch(r ->
            roleName.equals(r.getName())
                && Boolean.TRUE.equals(r.getClientRole())
                && clientUuid.equals(r.getContainerId()));
        if (alreadyPresent) {
            log.debug("ensureClientRoleInDefaultRoles: '{}:{}' already a composite of '{}'",
                clientId, roleName, defaultRoleName);
            return false;
        }
        defaultRole.addComposites(List.of(clientRole));
        log.info("ensureClientRoleInDefaultRoles: added '{}:{}' as composite of '{}' in realm '{}'",
            clientId, roleName, defaultRoleName, realmName);
        return true;
    }

    /** Creates a top-level authz scope on the client; no-op if it exists. */
    public void createAuthzScope(String realmName, String clientUuid, String scopeName) {
        AuthorizationResource authz = admin.realm(realmName).clients().get(clientUuid).authorization();
        ScopeRepresentation existing = authz.scopes().findByName(scopeName);
        if (existing != null) {
            return;
        }
        try (Response response = authz.scopes().create(new ScopeRepresentation(scopeName))) {
            requireSuccess(response, "create authz scope " + scopeName);
        }
    }

    /**
     * Creates an authz resource bound to the given scopes; no-op if the
     * resource already exists (scopes are NOT diffed in v1).
     */
    public void createAuthzResource(String realmName, String clientUuid,
                                    String resourceName, Set<String> scopeNames) {
        AuthorizationResource authz = admin.realm(realmName).clients().get(clientUuid).authorization();
        List<ResourceRepresentation> matches = authz.resources().findByName(resourceName);
        if (matches != null && !matches.isEmpty()) {
            return;
        }
        Set<ScopeRepresentation> scopes = new HashSet<>();
        for (String s : scopeNames) {
            scopes.add(new ScopeRepresentation(s));
        }
        ResourceRepresentation rr = new ResourceRepresentation();
        rr.setName(resourceName);
        rr.setScopes(scopes);
        try (Response response = authz.resources().create(rr)) {
            requireSuccess(response, "create authz resource " + resourceName);
        }
    }

    /**
     * Creates a role-based policy that grants the given client role. Returns
     * the policy ID. If a policy with this name already exists, returns its
     * existing ID.
     *
     * <p>{@code clientUuid} is the KC internal id (used for the path).
     * {@code oidcClientId} is the OAuth2 client_id (used in the role binding).
     * Keycloak's {@link RolePolicyRepresentation#addClientRole(String, String)}
     * expects the OIDC client_id string, NOT the internal UUID -- passing the
     * UUID causes HTTP 500 from the server.
     */
    public String createRolePolicy(String realmName, String clientUuid,
                                   String oidcClientId,
                                   String policyName, String roleName) {
        AuthorizationResource authz = admin.realm(realmName).clients().get(clientUuid).authorization();
        RolePolicyRepresentation existing = authz.policies().role().findByName(policyName);
        if (existing != null) {
            return existing.getId();
        }
        RolePolicyRepresentation rp = new RolePolicyRepresentation();
        rp.setName(policyName);
        rp.setLogic(Logic.POSITIVE);
        rp.setDecisionStrategy(DecisionStrategy.UNANIMOUS);
        // Bind to the client's role. addClientRole expects the OIDC client_id
        // (e.g. "orders"), NOT Keycloak's internal client UUID.
        rp.addClientRole(oidcClientId, roleName);
        try (Response response = authz.policies().role().create(rp)) {
            requireSuccess(response, "create role policy " + policyName);
        }
        RolePolicyRepresentation created = authz.policies().role().findByName(policyName);
        if (created == null) {
            throw new IllegalStateException("Role policy " + policyName + " not found after create");
        }
        return created.getId();
    }

    /**
     * Creates a scope-based permission binding the given resource + scopes to
     * the given policy IDs. No-op if a permission with this name already exists.
     */
    public void createScopePermission(String realmName, String clientUuid,
                                      String permissionName, String resourceName,
                                      Set<String> scopeNames, Set<String> policyIds) {
        AuthorizationResource authz = admin.realm(realmName).clients().get(clientUuid).authorization();
        ScopePermissionRepresentation existing = authz.permissions().scope().findByName(permissionName);
        if (existing != null) {
            return;
        }
        ScopePermissionRepresentation spr = new ScopePermissionRepresentation();
        spr.setName(permissionName);
        spr.setResources(new HashSet<>(Set.of(resourceName)));
        spr.setScopes(new HashSet<>(scopeNames));
        spr.setPolicies(new HashSet<>(policyIds));
        spr.setLogic(Logic.POSITIVE);
        spr.setDecisionStrategy(DecisionStrategy.UNANIMOUS);
        try (Response response = authz.permissions().scope().create(spr)) {
            requireSuccess(response, "create scope permission " + permissionName);
        }
    }

    // -----------------------------------------------------------------------
    // User bootstrap operations.
    // -----------------------------------------------------------------------

    /**
     * Creates a user in the given realm. Returns the user UUID.
     * If a user with the same username already exists, returns the existing
     * UUID instead of failing (idempotent).
     */
    public String createUser(String realmName, String username, String email,
                              String firstName, String lastName) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEnabled(true);
        user.setEmailVerified(false);  // they'll verify by clicking the link in the email

        try (Response response = admin.realm(realmName).users().create(user)) {
            if (response.getStatus() == 409) {
                // Already exists -- look up by username.
                var existing = admin.realm(realmName).users().searchByUsername(username, true);
                if (existing.isEmpty()) {
                    throw new RuntimeException("User " + username + " reported as conflict but not found");
                }
                return existing.get(0).getId();
            }
            if (response.getStatus() < 200 || response.getStatus() >= 300) {
                throw new RuntimeException(
                    "Create user failed: HTTP " + response.getStatus() + " " + response.getStatusInfo().getReasonPhrase());
            }
            String location = response.getHeaderString("Location");
            return location.substring(location.lastIndexOf('/') + 1);
        }
    }

    /**
     * Assigns a client role to a user. Idempotent: KC silently no-ops if the
     * user already has the role.
     */
    public void assignClientRoleToUser(String realmName, String userId,
                                       String clientId, String roleName) {
        String clientUuid = findClientUuid(realmName, clientId)
            .orElseThrow(() -> new IllegalStateException("Client not found: " + clientId));
        var role = admin.realm(realmName).clients().get(clientUuid)
                        .roles().get(roleName).toRepresentation();
        admin.realm(realmName).users().get(userId)
             .roles().clientLevel(clientUuid).add(java.util.List.of(role));
    }

    /**
     * Triggers Keycloak's "execute actions" email flow. KC emails the user
     * a one-time link to complete the listed actions (UPDATE_PASSWORD,
     * VERIFY_EMAIL, etc.). Uses the realm's configured SMTP server.
     *
     * @param lifespanSeconds how long the link is valid (e.g., 86400 = 24h)
     */
    public void sendExecuteActionsEmail(String realmName, String userId,
                                        java.util.List<String> actions,
                                        int lifespanSeconds) {
        admin.realm(realmName).users().get(userId)
             .executeActionsEmail(actions, lifespanSeconds);
    }

    /**
     * Lists users in a realm with optional substring search across username/email.
     * Returns a slice -- KC pagination uses first + max, not Spring's page-based
     * model. Callers do the conversion.
     */
    public java.util.List<UserRepresentation> listUsers(
        String realmName, String search, int first, int max
    ) {
        if (search == null || search.isBlank()) {
            return admin.realm(realmName).users().list(first, max);
        }
        return admin.realm(realmName).users().search(search, first, max);
    }

    /** Total user count in a realm (for pagination metadata). */
    public int countUsers(String realmName, String search) {
        return search == null || search.isBlank()
            ? admin.realm(realmName).users().count()
            : admin.realm(realmName).users().count(search);
    }

    /**
     * Lists users that hold the given realm role (composite-membership
     * lookup via {@code GET /admin/realms/{realm}/roles/{roleName}/users}).
     *
     * <p>Returns an empty list (NOT a 404) when the role doesn't exist so
     * callers can stay defensive without try/catch. KC's role-members
     * endpoint does NOT support a free-text search param -- callers that need
     * search filtering should apply it in-memory on the returned page.
     */
    public java.util.List<UserRepresentation> listUsersByRealmRole(
        String realmName, String roleName, int first, int max
    ) {
        try {
            var members = admin.realm(realmName).roles().get(roleName)
                .getUserMembers(first, max);
            return members == null ? java.util.List.of() : members;
        } catch (NotFoundException e) {
            return java.util.List.of();
        }
    }

    /** Realm-level role names currently assigned to a user. */
    public java.util.List<String> getUserRealmRoles(String realmName, String userId) {
        var assigned = admin.realm(realmName).users().get(userId).roles().realmLevel().listAll();
        return assigned.stream().map(RoleRepresentation::getName).toList();
    }

    /** Single user representation (basic fields). */
    public UserRepresentation getUser(String realmName, String userId) {
        return admin.realm(realmName).users().get(userId).toRepresentation();
    }

    /** Client-level role names currently assigned to a user on a given client. */
    public java.util.List<String> getUserClientRoles(
        String realmName, String userId, String clientId
    ) {
        String clientUuid = findClientUuid(realmName, clientId)
            .orElseThrow(() -> new IllegalStateException("Client not found: " + clientId));
        return admin.realm(realmName).users().get(userId)
            .roles().clientLevel(clientUuid).listAll()
            .stream().map(r -> r.getName()).toList();
    }

    /** Disables a user (soft-delete). Idempotent. */
    public void disableUser(String realmName, String userId) {
        UserRepresentation u = getUser(realmName, userId);
        if (u.isEnabled() == null || u.isEnabled()) {
            u.setEnabled(false);
            admin.realm(realmName).users().get(userId).update(u);
        }
    }

    /** Removes a client-level role from a user. Idempotent. */
    public void removeClientRoleFromUser(
        String realmName, String userId, String clientId, String roleName
    ) {
        String clientUuid = findClientUuid(realmName, clientId)
            .orElseThrow(() -> new IllegalStateException("Client not found: " + clientId));
        var role = admin.realm(realmName).clients().get(clientUuid)
            .roles().get(roleName).toRepresentation();
        admin.realm(realmName).users().get(userId)
            .roles().clientLevel(clientUuid).remove(java.util.List.of(role));
    }

    private void requireSuccess(Response response, String op) {
        int status = response.getStatus();
        if (status < 200 || status >= 300) {
            String reason = response.getStatusInfo().getReasonPhrase();
            log.error("Keycloak {} failed: HTTP {} {}", op, status, reason);
            throw new RuntimeException("Keycloak " + op + " failed: HTTP " + status + " " + reason);
        }
    }
}
