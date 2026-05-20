package io.mcpmesh.auth.manager.keycloak;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
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

        admin.realms().create(realm);
        return realmName;
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

    // -----------------------------------------------------------------------
    // Authorization model mutations (client-scoped, idempotent).
    //
    // All methods below check existence first and skip if the target already
    // exists. This lets ManifestService re-apply after a partial failure
    // without erroring on already-created resources.
    // -----------------------------------------------------------------------

    /** Enables Authorization Services on the client (no-op if already enabled). */
    public void enableAuthz(String realmName, String clientUuid) {
        ClientResource clientResource = admin.realm(realmName).clients().get(clientUuid);
        ClientRepresentation rep = clientResource.toRepresentation();
        if (Boolean.TRUE.equals(rep.getAuthorizationServicesEnabled())) {
            return;
        }
        rep.setAuthorizationServicesEnabled(Boolean.TRUE);
        // Confidential clients are required for authz services.
        rep.setServiceAccountsEnabled(Boolean.TRUE);
        rep.setPublicClient(Boolean.FALSE);
        clientResource.update(rep);
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

    private void requireSuccess(Response response, String op) {
        int status = response.getStatus();
        if (status < 200 || status >= 300) {
            String reason = response.getStatusInfo().getReasonPhrase();
            log.error("Keycloak {} failed: HTTP {} {}", op, status, reason);
            throw new RuntimeException("Keycloak " + op + " failed: HTTP " + status + " " + reason);
        }
    }
}
