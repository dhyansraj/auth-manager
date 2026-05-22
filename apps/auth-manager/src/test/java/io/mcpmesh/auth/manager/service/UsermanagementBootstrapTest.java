package io.mcpmesh.auth.manager.service;

import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import jakarta.ws.rs.NotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.mockito.ArgumentCaptor;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link KeycloakAdminService#ensureClientRoleInDefaultRoles},
 * the per-tenant + backfill primitive that wires {@code usermanagement:user-viewer}
 * into the realm's built-in {@code default-roles-<realm>} so brokered users
 * (Google/GitHub via KC's First Broker Login flow) land with a baseline role.
 *
 * <p>Stubs the Keycloak admin client; no real KC server required.
 */
class UsermanagementBootstrapTest {

    private static final String REALM = "t-app1";
    private static final String CLIENT_ID = "usermanagement";
    private static final String CLIENT_UUID = "um-uuid";
    private static final String ROLE_NAME = "user-viewer";
    private static final String DEFAULT_ROLE_NAME = "default-roles-t-app1";

    private Keycloak admin;
    private RealmResource realm;
    private ClientsResource clientsResource;
    private ClientResource clientResource;
    private RolesResource clientRolesResource;
    private RoleResource clientRoleResource;
    private RolesResource realmRolesResource;
    private RoleResource defaultRoleResource;

    private KeycloakAdminService service;

    @BeforeEach
    void setUp() {
        admin = mock(Keycloak.class);
        realm = mock(RealmResource.class);
        clientsResource = mock(ClientsResource.class);
        clientResource = mock(ClientResource.class);
        clientRolesResource = mock(RolesResource.class);
        clientRoleResource = mock(RoleResource.class);
        realmRolesResource = mock(RolesResource.class);
        defaultRoleResource = mock(RoleResource.class);

        when(admin.realm(REALM)).thenReturn(realm);
        when(realm.clients()).thenReturn(clientsResource);
        when(realm.roles()).thenReturn(realmRolesResource);

        service = new KeycloakAdminService(admin);
    }

    /** Wires up `findByClientId(usermanagement) -> [um-uuid]` and the role chain. */
    private void stubClientExists() {
        ClientRepresentation c = new ClientRepresentation();
        c.setId(CLIENT_UUID);
        c.setClientId(CLIENT_ID);
        when(clientsResource.findByClientId(CLIENT_ID)).thenReturn(List.of(c));
        when(clientsResource.get(CLIENT_UUID)).thenReturn(clientResource);
        when(clientResource.roles()).thenReturn(clientRolesResource);
        when(clientRolesResource.get(ROLE_NAME)).thenReturn(clientRoleResource);

        RoleRepresentation rep = new RoleRepresentation();
        rep.setName(ROLE_NAME);
        rep.setClientRole(true);
        rep.setContainerId(CLIENT_UUID);
        when(clientRoleResource.toRepresentation()).thenReturn(rep);
    }

    private void stubDefaultRoleExists(Set<RoleRepresentation> existingComposites) {
        when(realmRolesResource.get(DEFAULT_ROLE_NAME)).thenReturn(defaultRoleResource);
        RoleRepresentation defRep = new RoleRepresentation();
        defRep.setName(DEFAULT_ROLE_NAME);
        when(defaultRoleResource.toRepresentation()).thenReturn(defRep);
        when(defaultRoleResource.getRoleComposites()).thenReturn(existingComposites);
    }

    @Test
    void newRealmBootstrap_addsUserViewerAsCompositeOfDefaultRoles() {
        stubClientExists();
        stubDefaultRoleExists(new HashSet<>());  // no composites yet

        boolean added = service.ensureClientRoleInDefaultRoles(REALM, CLIENT_ID, ROLE_NAME);

        assertThat(added).isTrue();

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<RoleRepresentation>> cap = ArgumentCaptor.forClass(List.class);
        verify(defaultRoleResource, times(1)).addComposites(cap.capture());

        List<RoleRepresentation> added2 = cap.getValue();
        assertThat(added2).hasSize(1);
        RoleRepresentation r = added2.get(0);
        assertThat(r.getName()).isEqualTo(ROLE_NAME);
        assertThat(r.getClientRole()).isTrue();
        assertThat(r.getContainerId()).isEqualTo(CLIENT_UUID);
    }

    @Test
    void reRunOnRealmWhereCompositeAlreadyExists_isIdempotentNoOp() {
        stubClientExists();

        // Existing composite: the client role we're about to add.
        RoleRepresentation already = new RoleRepresentation();
        already.setName(ROLE_NAME);
        already.setClientRole(true);
        already.setContainerId(CLIENT_UUID);
        stubDefaultRoleExists(new HashSet<>(Set.of(already)));

        boolean added = service.ensureClientRoleInDefaultRoles(REALM, CLIENT_ID, ROLE_NAME);

        assertThat(added).isFalse();
        verify(defaultRoleResource, never()).addComposites(anyList());
    }

    @Test
    void realmWithoutUsermanagementClient_logsWarnAndSkips() {
        // No client matches by clientId.
        when(clientsResource.findByClientId(CLIENT_ID)).thenReturn(List.of());

        boolean added = service.ensureClientRoleInDefaultRoles(REALM, CLIENT_ID, ROLE_NAME);

        assertThat(added).isFalse();
        // Should never even attempt to touch the realm roles.
        verify(realm, never()).roles();
        verify(defaultRoleResource, never()).addComposites(anyList());
    }

    @Test
    void missingDefaultRolesRole_logsWarnAndSkips() {
        // Defensive case: client exists, role exists, but default-roles-<realm>
        // is somehow missing (shouldn't happen in real KC, but guard anyway).
        stubClientExists();
        when(realmRolesResource.get(DEFAULT_ROLE_NAME)).thenReturn(defaultRoleResource);
        when(defaultRoleResource.toRepresentation()).thenThrow(new NotFoundException("nope"));

        boolean added = service.ensureClientRoleInDefaultRoles(REALM, CLIENT_ID, ROLE_NAME);

        assertThat(added).isFalse();
        verify(defaultRoleResource, never()).addComposites(any());
    }

    @Test
    void missingClientRole_logsWarnAndSkips() {
        // Client exists, but the named role doesn't.
        ClientRepresentation c = new ClientRepresentation();
        c.setId(CLIENT_UUID);
        c.setClientId(CLIENT_ID);
        when(clientsResource.findByClientId(CLIENT_ID)).thenReturn(List.of(c));
        when(clientsResource.get(CLIENT_UUID)).thenReturn(clientResource);
        when(clientResource.roles()).thenReturn(clientRolesResource);
        when(clientRolesResource.get(ROLE_NAME)).thenReturn(clientRoleResource);
        when(clientRoleResource.toRepresentation()).thenThrow(new NotFoundException("missing"));

        boolean added = service.ensureClientRoleInDefaultRoles(REALM, CLIENT_ID, ROLE_NAME);

        assertThat(added).isFalse();
        verify(realm, never()).roles();
    }
}
