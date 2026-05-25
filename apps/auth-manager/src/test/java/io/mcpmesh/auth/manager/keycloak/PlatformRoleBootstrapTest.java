package io.mcpmesh.auth.manager.keycloak;

import io.mcpmesh.auth.manager.service.PlatformPermissions;
import io.mcpmesh.auth.manager.service.UsermanagementBootstrap;
import jakarta.ws.rs.NotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.admin.client.resource.RoleScopeResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PlatformRoleBootstrap}. Stubs the Keycloak admin
 * client so we don't need a real KC server.
 */
class PlatformRoleBootstrapTest {

    private static final String REALM = "dev";
    private static final String ROLE = "platform-admin";
    private static final String USERNAME = "admin";
    private static final String HOST = "auth.mcp-mesh.io";
    private static final String NEW_CLIENT_UUID = "new-client-uuid";
    private static final String EXISTING_CLIENT_UUID = "existing-client-uuid";

    private Keycloak admin;
    private RealmResource realm;
    private RolesResource roles;
    private RoleResource roleResource;
    private UsersResource users;
    private UserResource userResource;
    private RoleMappingResource roleMappings;
    private RoleScopeResource realmLevelMapping;
    private KeycloakProperties props;
    private KeycloakAdminService keycloakAdminService;

    @BeforeEach
    void setUp() {
        admin = mock(Keycloak.class);
        realm = mock(RealmResource.class);
        roles = mock(RolesResource.class);
        roleResource = mock(RoleResource.class);
        users = mock(UsersResource.class);
        userResource = mock(UserResource.class);
        roleMappings = mock(RoleMappingResource.class);
        realmLevelMapping = mock(RoleScopeResource.class);
        keycloakAdminService = mock(KeycloakAdminService.class);

        when(admin.realm(REALM)).thenReturn(realm);
        when(realm.roles()).thenReturn(roles);
        when(realm.users()).thenReturn(users);

        // Default: dev realm has no usermanagement client. The bootstrap is
        // now expected to CREATE it (rather than skipping as before).
        when(keycloakAdminService.findClientUuid(anyString(), anyString()))
            .thenReturn(Optional.empty());
        when(keycloakAdminService.createPublicClient(anyString(), anyString(), anyString()))
            .thenReturn(NEW_CLIENT_UUID);

        props = new KeycloakProperties(
            "http://localhost:8180", "master",
            new KeycloakProperties.Admin("admin-cli", USERNAME, "admin"),
            new KeycloakProperties.Platform(REALM, ROLE, HOST),
            null, null
        );
    }

    @Test
    void skipsGracefully_whenRealmMissing() {
        when(realm.toRepresentation()).thenThrow(new NotFoundException("nope"));

        new PlatformRoleBootstrap(admin, props, keycloakAdminService).run(null);

        verify(roles, never()).create(any());
    }

    @Test
    void createsRole_whenMissing_andGrantsToAdmin() {
        // Realm exists.
        when(realm.toRepresentation()).thenReturn(new RealmRepresentation());

        // Role lookup: first throws NotFound (so we create), then returns the role on re-fetch.
        RoleRepresentation created = new RoleRepresentation();
        created.setName(ROLE);
        when(roles.get(ROLE)).thenReturn(roleResource);
        when(roleResource.toRepresentation())
            .thenThrow(new NotFoundException("missing"))
            .thenReturn(created);

        // Admin user found.
        UserRepresentation user = new UserRepresentation();
        user.setId("user-uuid");
        user.setUsername(USERNAME);
        when(users.searchByUsername(USERNAME, true)).thenReturn(List.of(user));
        when(users.get("user-uuid")).thenReturn(userResource);
        when(userResource.roles()).thenReturn(roleMappings);
        when(roleMappings.realmLevel()).thenReturn(realmLevelMapping);
        // User has no effective realm roles yet.
        when(realmLevelMapping.listEffective()).thenReturn(new ArrayList<>());

        new PlatformRoleBootstrap(admin, props, keycloakAdminService).run(null);

        verify(roles).create(any(RoleRepresentation.class));
        verify(realmLevelMapping, times(1)).add(any());
    }

    @Test
    void isIdempotent_whenRoleAndGrantAlreadyExist() {
        when(realm.toRepresentation()).thenReturn(new RealmRepresentation());

        RoleRepresentation existing = new RoleRepresentation();
        existing.setName(ROLE);
        when(roles.get(ROLE)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(existing);

        UserRepresentation user = new UserRepresentation();
        user.setId("user-uuid");
        when(users.searchByUsername(USERNAME, true)).thenReturn(List.of(user));
        when(users.get("user-uuid")).thenReturn(userResource);
        when(userResource.roles()).thenReturn(roleMappings);
        when(roleMappings.realmLevel()).thenReturn(realmLevelMapping);

        RoleRepresentation alreadyGranted = new RoleRepresentation();
        alreadyGranted.setName(ROLE);
        when(realmLevelMapping.listEffective()).thenReturn(List.of(alreadyGranted));

        new PlatformRoleBootstrap(admin, props, keycloakAdminService).run(null);

        // No role create, no add-grant.
        verify(roles, never()).create(any());
        verify(realmLevelMapping, never()).add(any());
    }

    @Test
    void skipsGrant_whenUserMissing_butStillCreatesRole() {
        when(realm.toRepresentation()).thenReturn(new RealmRepresentation());

        RoleRepresentation created = new RoleRepresentation();
        created.setName(ROLE);
        when(roles.get(ROLE)).thenReturn(roleResource);
        when(roleResource.toRepresentation())
            .thenThrow(new NotFoundException("missing"))
            .thenReturn(created);

        when(users.searchByUsername(USERNAME, true)).thenReturn(List.of());

        new PlatformRoleBootstrap(admin, props, keycloakAdminService).run(null);

        verify(roles, times(1)).create(any(RoleRepresentation.class));
        // realmLevel() never traversed because we bailed before grant.
        verify(roleMappings, never()).realmLevel();
    }

    @Test
    void doesNotThrow_whenKeycloakIsUnreachable() {
        when(realm.toRepresentation()).thenThrow(new RuntimeException("connection refused"));
        // Must not propagate.
        new PlatformRoleBootstrap(admin, props, keycloakAdminService).run(null);
    }

    // -------------------------------------------------------------------
    // usermanagement client bootstrap (new behaviour)
    // -------------------------------------------------------------------

    /** Default happy path: realm exists, role exists, admin user found + granted. */
    private void wireHappyRealmAndUser() {
        when(realm.toRepresentation()).thenReturn(new RealmRepresentation());
        RoleRepresentation existingRole = new RoleRepresentation();
        existingRole.setName(ROLE);
        when(roles.get(ROLE)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenReturn(existingRole);
        UserRepresentation user = new UserRepresentation();
        user.setId("user-uuid");
        when(users.searchByUsername(USERNAME, true)).thenReturn(List.of(user));
        when(users.get("user-uuid")).thenReturn(userResource);
        when(userResource.roles()).thenReturn(roleMappings);
        when(roleMappings.realmLevel()).thenReturn(realmLevelMapping);
        RoleRepresentation granted = new RoleRepresentation();
        granted.setName(ROLE);
        when(realmLevelMapping.listEffective()).thenReturn(List.of(granted));
    }

    @Test
    void createsUsermanagementClient_whenMissing_andWiresEverything() {
        wireHappyRealmAndUser();
        // Default findClientUuid -> Optional.empty() (from setUp), so the
        // bootstrap is expected to call createPublicClient.

        new PlatformRoleBootstrap(admin, props, keycloakAdminService).run(null);

        // 1. Client created with the canonical slug + display name.
        verify(keycloakAdminService, times(1)).createPublicClient(
            eq(REALM),
            eq(UsermanagementBootstrap.CLIENT_SLUG),
            eq(UsermanagementBootstrap.DISPLAY_NAME));

        // 2. Redirect URIs declared with isDevRealm=true and no tenant hosts.
        verify(keycloakAdminService, times(1)).setStandardRedirectUris(
            eq(REALM), eq(NEW_CLIENT_UUID), eq(List.of()), eq(HOST), eq(true));

        // 3. Client attributes installed (PKCE-S256, backchannel-logout URL + toggles).
        ArgumentCaptor<Map<String, String>> attrsCap = ArgumentCaptor.forClass(Map.class);
        verify(keycloakAdminService, times(1)).setClientAttributes(
            eq(REALM), eq(NEW_CLIENT_UUID), attrsCap.capture());
        Map<String, String> attrs = attrsCap.getValue();
        assertThat(attrs).containsEntry("pkce.code.challenge.method", "S256");
        assertThat(attrs).containsEntry("backchannel.logout.url",
            "https://" + HOST + "/_bff/backchannel-logout");
        assertThat(attrs).containsEntry("backchannel.logout.session.required", "true");
        assertThat(attrs).containsEntry("backchannel.logout.revoke.offline.tokens", "true");

        // 4. Composite tenant client roles ensured (tenant-admin, tenant-user-manager, user-viewer).
        verify(keycloakAdminService, times(1)).createClientRole(
            REALM, NEW_CLIENT_UUID, UsermanagementBootstrap.ROLE_TENANT_ADMIN);
        verify(keycloakAdminService, times(1)).createClientRole(
            REALM, NEW_CLIENT_UUID, UsermanagementBootstrap.ROLE_TENANT_USER_MANAGER);
        verify(keycloakAdminService, times(1)).createClientRole(
            REALM, NEW_CLIENT_UUID, UsermanagementBootstrap.ROLE_USER_VIEWER);

        // 5. Every atomic perm (platform + tenant level) installed as a flat client role.
        for (String perm : PlatformPermissions.PLATFORM_PERMS) {
            verify(keycloakAdminService, times(1)).createClientRole(REALM, NEW_CLIENT_UUID, perm);
        }
        for (String perm : PlatformPermissions.TENANT_ADMIN_BUNDLE) {
            verify(keycloakAdminService, times(1)).createClientRole(REALM, NEW_CLIENT_UUID, perm);
        }

        // 6. Composite wiring: tenant-admin -> TENANT_ADMIN_BUNDLE,
        //    tenant-user-manager -> TENANT_USER_MANAGER_BUNDLE.
        verify(keycloakAdminService, times(1)).ensureClientRoleComposites(
            REALM, NEW_CLIENT_UUID,
            UsermanagementBootstrap.ROLE_TENANT_ADMIN,
            PlatformPermissions.TENANT_ADMIN_BUNDLE);
        verify(keycloakAdminService, times(1)).ensureClientRoleComposites(
            REALM, NEW_CLIENT_UUID,
            UsermanagementBootstrap.ROLE_TENANT_USER_MANAGER,
            PlatformPermissions.TENANT_USER_MANAGER_BUNDLE);

        // 7. platform-admin realm role wired to include every atomic perm.
        ArgumentCaptor<List<String>> permsCap = ArgumentCaptor.forClass(List.class);
        verify(keycloakAdminService, times(1)).ensureRealmRoleClientComposites(
            eq(REALM), eq(ROLE), eq(NEW_CLIENT_UUID), permsCap.capture());
        List<String> wiredPerms = permsCap.getValue();
        assertThat(wiredPerms).containsAll(PlatformPermissions.PLATFORM_PERMS);
        assertThat(wiredPerms).containsAll(PlatformPermissions.TENANT_ADMIN_BUNDLE);
    }

    @Test
    void usesExistingUsermanagementClient_andDoesNotRecreateIt() {
        wireHappyRealmAndUser();
        when(keycloakAdminService.findClientUuid(REALM, UsermanagementBootstrap.CLIENT_SLUG))
            .thenReturn(Optional.of(EXISTING_CLIENT_UUID));

        new PlatformRoleBootstrap(admin, props, keycloakAdminService).run(null);

        // Existing client -> no create call.
        verify(keycloakAdminService, never()).createPublicClient(anyString(), anyString(), anyString());
        // But wiring still happens, against the existing uuid.
        verify(keycloakAdminService, times(1)).setClientAttributes(
            eq(REALM), eq(EXISTING_CLIENT_UUID), anyMap());
        verify(keycloakAdminService, times(1)).setStandardRedirectUris(
            eq(REALM), eq(EXISTING_CLIENT_UUID), anyList(), eq(HOST), eq(true));
        verify(keycloakAdminService, times(1)).ensureRealmRoleClientComposites(
            eq(REALM), eq(ROLE), eq(EXISTING_CLIENT_UUID), anyList());
    }

    @Test
    void skipsClientWiring_whenCreatePublicClientFails() {
        wireHappyRealmAndUser();
        when(keycloakAdminService.createPublicClient(anyString(), anyString(), anyString()))
            .thenThrow(new RuntimeException("KC returned 500"));

        // Must not propagate.
        new PlatformRoleBootstrap(admin, props, keycloakAdminService).run(null);

        verify(keycloakAdminService, times(1)).createPublicClient(
            REALM, UsermanagementBootstrap.CLIENT_SLUG, UsermanagementBootstrap.DISPLAY_NAME);
        // No follow-up wiring since we never got a uuid.
        verify(keycloakAdminService, never()).setClientAttributes(anyString(), anyString(), anyMap());
        verify(keycloakAdminService, never()).setStandardRedirectUris(
            anyString(), anyString(), anyList(), anyString(), eq(true));
        verify(keycloakAdminService, never()).ensureRealmRoleClientComposites(
            anyString(), anyString(), anyString(), anyList());
    }
}
