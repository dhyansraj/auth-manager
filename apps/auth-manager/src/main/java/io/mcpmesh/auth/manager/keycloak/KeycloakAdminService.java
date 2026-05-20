package io.mcpmesh.auth.manager.keycloak;

import jakarta.ws.rs.NotFoundException;
import org.keycloak.admin.client.Keycloak;
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
}
