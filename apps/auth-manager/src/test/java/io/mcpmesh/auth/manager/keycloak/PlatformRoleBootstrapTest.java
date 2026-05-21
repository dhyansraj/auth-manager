package io.mcpmesh.auth.manager.keycloak;

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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
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

    private Keycloak admin;
    private RealmResource realm;
    private RolesResource roles;
    private RoleResource roleResource;
    private UsersResource users;
    private UserResource userResource;
    private RoleMappingResource roleMappings;
    private RoleScopeResource realmLevelMapping;
    private KeycloakProperties props;

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

        when(admin.realm(REALM)).thenReturn(realm);
        when(realm.roles()).thenReturn(roles);
        when(realm.users()).thenReturn(users);

        props = new KeycloakProperties(
            "http://localhost:8180", "master",
            new KeycloakProperties.Admin("admin-cli", USERNAME, "admin"),
            new KeycloakProperties.Platform(REALM, ROLE),
            null, null
        );
    }

    @Test
    void skipsGracefully_whenRealmMissing() {
        when(realm.toRepresentation()).thenThrow(new NotFoundException("nope"));

        new PlatformRoleBootstrap(admin, props).run(null);

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

        new PlatformRoleBootstrap(admin, props).run(null);

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

        new PlatformRoleBootstrap(admin, props).run(null);

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

        new PlatformRoleBootstrap(admin, props).run(null);

        verify(roles, times(1)).create(any(RoleRepresentation.class));
        // realmLevel() never traversed because we bailed before grant.
        verify(roleMappings, never()).realmLevel();
    }

    @Test
    void doesNotThrow_whenKeycloakIsUnreachable() {
        when(realm.toRepresentation()).thenThrow(new RuntimeException("connection refused"));
        // Must not propagate.
        new PlatformRoleBootstrap(admin, props).run(null);
    }
}
