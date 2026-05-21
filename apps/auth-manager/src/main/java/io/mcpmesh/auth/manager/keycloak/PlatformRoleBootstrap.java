package io.mcpmesh.auth.manager.keycloak;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Idempotently ensures the cross-tenant platform-admin realm role exists in
 * the configured platform realm (default: {@code dev}) and is granted to the
 * configured admin user (default: {@code admin}).
 *
 * <p>The realm is expected to already exist via the seed import (see
 * {@code dev/seed/realm.json}). If the realm or user is missing this
 * bootstrap logs a warning and skips -- it never crashes the app, since the
 * platform-admin bypass is opportunistic; per-tenant role checks still work
 * without it.
 *
 * <p>Runs as an {@link ApplicationRunner} (not {@code @PostConstruct}) so
 * that the Keycloak admin client has a chance to acquire its initial token
 * after the rest of the context is up.
 */
@Component
public class PlatformRoleBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(PlatformRoleBootstrap.class);

    private final Keycloak admin;
    private final KeycloakProperties props;

    public PlatformRoleBootstrap(Keycloak admin, KeycloakProperties props) {
        this.admin = admin;
        this.props = props;
    }

    @Override
    public void run(ApplicationArguments args) {
        var platform = props.platform();
        if (platform == null) {
            log.info("PlatformRoleBootstrap: no keycloak.platform config — skipping");
            return;
        }
        String realmName = platform.realm();
        String roleName  = platform.role();
        String username  = props.admin().username();

        try {
            RealmResource realm;
            try {
                admin.realm(realmName).toRepresentation();
                realm = admin.realm(realmName);
            } catch (NotFoundException e) {
                log.warn("PlatformRoleBootstrap: platform realm '{}' not found — skipping (run KC seed?)", realmName);
                return;
            } catch (Exception e) {
                log.warn("PlatformRoleBootstrap: unable to reach platform realm '{}': {} — skipping", realmName, e.getMessage());
                return;
            }

            // 1. Ensure the realm role exists.
            RoleRepresentation role;
            try {
                role = realm.roles().get(roleName).toRepresentation();
                log.info("PlatformRoleBootstrap: realm role '{}' already exists in '{}'", roleName, realmName);
            } catch (NotFoundException e) {
                RoleRepresentation toCreate = new RoleRepresentation();
                toCreate.setName(roleName);
                toCreate.setDescription("Cross-tenant platform-admin bypass for auth-manager");
                try (Response r = createRoleAndReturnResponse(realm, toCreate)) {
                    // realms().roles().create() returns void in some KC client versions;
                    // we handle both via createRoleAndReturnResponse helper below.
                }
                role = realm.roles().get(roleName).toRepresentation();
                log.info("PlatformRoleBootstrap: created realm role '{}' in '{}'", roleName, realmName);
            }

            // 2. Find the admin user; if missing, log + skip the grant.
            List<UserRepresentation> matches = realm.users().searchByUsername(username, true);
            if (matches.isEmpty()) {
                log.warn("PlatformRoleBootstrap: user '{}' not found in realm '{}' — role created but not granted",
                    username, realmName);
                return;
            }
            String userId = matches.get(0).getId();

            // 3. Grant the role to the user (idempotent: KC silently no-ops on re-add).
            var currentRoles = realm.users().get(userId).roles().realmLevel().listEffective();
            boolean alreadyHas = currentRoles.stream().anyMatch(r -> roleName.equals(r.getName()));
            if (alreadyHas) {
                log.info("PlatformRoleBootstrap: user '{}' already has realm role '{}' in '{}'",
                    username, roleName, realmName);
            } else {
                realm.users().get(userId).roles().realmLevel().add(List.of(role));
                log.info("PlatformRoleBootstrap: granted realm role '{}' to user '{}' in '{}'",
                    roleName, username, realmName);
            }
        } catch (Exception e) {
            // Never fail the boot — this is a self-healing bootstrap.
            log.warn("PlatformRoleBootstrap: unexpected failure ({}) — continuing without platform-admin grant",
                e.getMessage(), e);
        }
    }

    /**
     * The Keycloak admin client's {@code roles().create()} returns void in
     * recent versions. We invoke it and return a no-op AutoCloseable so the
     * caller's try-with-resources reads naturally regardless of client minor.
     */
    private static Response createRoleAndReturnResponse(RealmResource realm, RoleRepresentation rep) {
        realm.roles().create(rep);
        return Response.ok().build();
    }
}
