package io.mcpmesh.auth.manager.keycloak;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.info.ServerInfoRepresentation;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Read-only Keycloak admin operations used by health checks and discovery.
 * Mutating operations (create realm, create client, etc.) get their own
 * services as Phase 1 progresses.
 */
@Service
public class KeycloakAdminService {

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
}
