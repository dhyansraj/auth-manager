package io.mcpmesh.auth.manager.keycloak;

import io.mcpmesh.auth.manager.service.PlatformPermissions;
import io.mcpmesh.auth.manager.service.UsermanagementBootstrap;
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

import java.util.ArrayList;
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
    private final KeycloakAdminService keycloak;

    public PlatformRoleBootstrap(Keycloak admin,
                                 KeycloakProperties props,
                                 KeycloakAdminService keycloak) {
        this.admin = admin;
        this.props = props;
        this.keycloak = keycloak;
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

            // 4. Materialize the atomic permission catalog (Phase A of the
            //    admin-ui permission migration) on the dev realm and wire the
            //    platform-admin realm role as a composite that includes:
            //    a) all PLATFORM_PERMS (platform-wide capabilities)
            //    b) all TENANT_ADMIN_BUNDLE perms (so platform-admin's /me
            //       returns every tenant-level perm too -- matches today's
            //       cross-tenant bypass semantics).
            //    Best-effort: failures here don't abort the bootstrap since
            //    the role-based bypass in TenantSecurity still works without
            //    these atomic perms in place.
            wirePlatformAtomicPerms(realmName);
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

    /**
     * Ensures the dev realm's {@code usermanagement} client exists with the
     * canonical config (public PKCE-S256, BFF backchannel-logout endpoint,
     * redirect URIs) and has every atomic permission (platform + tenant
     * level) defined as a client role. Wires:
     *
     * <ul>
     *   <li>the composite tenant client roles ({@code tenant-admin},
     *       {@code tenant-user-manager}, {@code user-viewer}) so the dev
     *       realm mirrors the tenant-realm structure, and</li>
     *   <li>the {@code platform-admin} realm role as a composite of ALL
     *       atomic perms so KC flattens them into the JWT's
     *       {@code resource_access} claim for platform-admin users.</li>
     * </ul>
     *
     * <p>If the {@code usermanagement} client is missing it is created (public
     * OIDC client, PKCE-S256 required, standard flow on, direct grants +
     * service accounts off). Idempotent at every step — re-running on an
     * already-configured dev realm is a silent no-op.
     *
     * <p>Best-effort: a per-step failure logs WARN and continues so a single
     * bad step doesn't poison the rest of the bootstrap.
     */
    private void wirePlatformAtomicPerms(String realmName) {
        try {
            String platformHost = props.platform().host();

            // 1. Ensure the usermanagement client exists on the dev realm.
            //    Fresh deployments hit an operational cliff without this --
            //    admin-ui can't authenticate, platform-admin can't sign in.
            String clientUuid;
            var existing = keycloak.findClientUuid(
                realmName, UsermanagementBootstrap.CLIENT_SLUG);
            if (existing.isPresent()) {
                clientUuid = existing.get();
            } else {
                try {
                    clientUuid = keycloak.createPublicClient(
                        realmName,
                        UsermanagementBootstrap.CLIENT_SLUG,
                        UsermanagementBootstrap.DISPLAY_NAME);
                    log.info("PlatformRoleBootstrap: created '{}' client in realm '{}'",
                        UsermanagementBootstrap.CLIENT_SLUG, realmName);
                } catch (Exception e) {
                    log.warn("PlatformRoleBootstrap: failed to create '{}' client in realm '{}': {} — "
                        + "skipping platform client wiring",
                        UsermanagementBootstrap.CLIENT_SLUG, realmName, e.getMessage());
                    return;
                }
            }

            // 2. Declare the canonical redirect URIs + web origins. Dev has no
            //    tenant hosts so we pass an empty list with isDevRealm=true;
            //    the helper still installs the platform host + localhost dev
            //    variants.
            try {
                keycloak.setStandardRedirectUris(
                    realmName, clientUuid, java.util.List.of(), platformHost, true);
            } catch (Exception e) {
                log.warn("PlatformRoleBootstrap: redirect-URI wiring failed in realm '{}': {}",
                    realmName, e.getMessage());
            }

            // 3. Install the canonical client attributes: PKCE-S256, BFF
            //    backchannel-logout endpoint, and the two backchannel-logout
            //    behaviour toggles. Declarative — replaces any drift left by
            //    ad-hoc kcadm scripts. Idempotent.
            try {
                java.util.Map<String, String> attrs = new java.util.LinkedHashMap<>();
                attrs.put("pkce.code.challenge.method", "S256");
                if (platformHost != null && !platformHost.isBlank()) {
                    attrs.put("backchannel.logout.url",
                        "https://" + platformHost + "/_bff/backchannel-logout");
                }
                attrs.put("backchannel.logout.session.required", "true");
                attrs.put("backchannel.logout.revoke.offline.tokens", "true");
                keycloak.setClientAttributes(realmName, clientUuid, attrs);
            } catch (Exception e) {
                log.warn("PlatformRoleBootstrap: client-attribute wiring failed in realm '{}': {}",
                    realmName, e.getMessage());
            }

            // 4. Ensure the composite tenant client roles exist so the dev
            //    realm mirrors the tenant-realm structure (platform-admin
            //    users may need to hold these roles for tenant-scoped UI
            //    flows that read the dev realm).
            for (String roleName : List.of(
                UsermanagementBootstrap.ROLE_TENANT_ADMIN,
                UsermanagementBootstrap.ROLE_TENANT_USER_MANAGER,
                UsermanagementBootstrap.ROLE_USER_VIEWER
            )) {
                try {
                    keycloak.createClientRole(realmName, clientUuid, roleName);
                } catch (Exception e) {
                    log.warn("PlatformRoleBootstrap: failed to create client role '{}' on '{}' in realm '{}': {}",
                        roleName, UsermanagementBootstrap.CLIENT_SLUG, realmName, e.getMessage());
                }
            }

            // 5. Materialize every atomic perm (platform + tenant level) as a
            //    flat client role on dev/usermanagement. Idempotent.
            List<String> allPerms = new ArrayList<>();
            allPerms.addAll(PlatformPermissions.PLATFORM_PERMS);
            allPerms.addAll(PlatformPermissions.TENANT_ADMIN_BUNDLE);
            for (String perm : allPerms) {
                try {
                    keycloak.createClientRole(realmName, clientUuid, perm);
                } catch (Exception e) {
                    log.warn("PlatformRoleBootstrap: failed to create atomic perm '{}' "
                        + "on '{}' in realm '{}': {}",
                        perm, UsermanagementBootstrap.CLIENT_SLUG, realmName, e.getMessage());
                }
            }

            // 6. Wire the composite tenant client roles to include their
            //    matching atomic-perm bundles (mirrors UsermanagementBootstrap
            //    for tenant realms). Idempotent.
            try {
                keycloak.ensureClientRoleComposites(
                    realmName, clientUuid,
                    UsermanagementBootstrap.ROLE_TENANT_ADMIN,
                    PlatformPermissions.TENANT_ADMIN_BUNDLE);
                keycloak.ensureClientRoleComposites(
                    realmName, clientUuid,
                    UsermanagementBootstrap.ROLE_TENANT_USER_MANAGER,
                    PlatformPermissions.TENANT_USER_MANAGER_BUNDLE);
            } catch (Exception e) {
                log.warn("PlatformRoleBootstrap: tenant client-role composite wiring failed in realm '{}': {}",
                    realmName, e.getMessage());
            }

            // 7. Wire platform-admin realm role to include every atomic perm
            //    as a composite. Idempotent.
            String roleName = props.platform().role();
            try {
                keycloak.ensureRealmRoleClientComposites(
                    realmName, roleName, clientUuid, allPerms);
            } catch (Exception e) {
                log.warn("PlatformRoleBootstrap: failed to wire realm role '{}' composites "
                    + "in realm '{}': {}",
                    roleName, realmName, e.getMessage());
            }
        } catch (Exception e) {
            log.warn("PlatformRoleBootstrap: atomic-perm wiring failed in realm '{}': {}",
                realmName, e.getMessage());
        }
    }
}
