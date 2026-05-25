package io.mcpmesh.auth.manager.service;

import io.mcpmesh.auth.manager.api.dto.CreateUserRequest;
import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.UserRepresentation;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Pure-mock unit tests for {@link UserManagementService}. Verifies the
 * user-viewer baseline-role invariant on both create and updateRoles paths.
 */
class UserManagementServiceTest {

    private static final UUID TENANT_ID = UUID.randomUUID();
    private static final String REALM = "t-app1";
    private static final String USER_ID = "user-1";
    private static final String CLIENT = "usermanagement";

    private TenantService tenants;
    private KeycloakAdminService keycloak;
    private AuditService audit;
    private UserManagementService svc;

    @BeforeEach
    void setUp() {
        tenants = mock(TenantService.class);
        keycloak = mock(KeycloakAdminService.class);
        audit = mock(AuditService.class);

        Tenant t = mock(Tenant.class);
        when(t.getRealmName()).thenReturn(REALM);
        when(tenants.get(TENANT_ID)).thenReturn(t);

        // KC createUser returns the user id
        when(keycloak.createUser(eq(REALM), anyString(), anyString(), any(), any()))
            .thenReturn(USER_ID);

        // After create(), service does a get() round trip. Stub the bare
        // minimum to make it pass.
        UserRepresentation rep = new UserRepresentation();
        rep.setId(USER_ID);
        rep.setUsername("bob@app1.test");
        rep.setEmail("bob@app1.test");
        rep.setEnabled(true);
        when(keycloak.getUser(REALM, USER_ID)).thenReturn(rep);
        when(keycloak.getUserClientRoles(REALM, USER_ID, CLIENT))
            .thenReturn(new ArrayList<>(List.of("user-viewer")));

        svc = new UserManagementService(tenants, keycloak, audit);
    }

    @Test
    void create_withEmptyRoles_grantsUserViewer() {
        CreateUserRequest req = new CreateUserRequest(
            "bob@app1.test", "Bob", "Test", List.of(), false);

        svc.create(TENANT_ID, req, "alice");

        // Should assign user-viewer exactly once and nothing else.
        verify(keycloak).assignClientRoleToUser(REALM, USER_ID, CLIENT, "user-viewer");
        verify(keycloak, never()).assignClientRoleToUser(REALM, USER_ID, CLIENT, "tenant-admin");
    }

    @Test
    void create_withNullRoles_grantsUserViewer() {
        CreateUserRequest req = new CreateUserRequest(
            "bob@app1.test", "Bob", "Test", null, false);

        svc.create(TENANT_ID, req, "alice");

        verify(keycloak).assignClientRoleToUser(REALM, USER_ID, CLIENT, "user-viewer");
        verify(keycloak, never()).assignClientRoleToUser(REALM, USER_ID, CLIENT, "tenant-admin");
    }

    @Test
    void create_withTenantAdminRole_grantsBothRoles() {
        CreateUserRequest req = new CreateUserRequest(
            "bob@app1.test", "Bob", "Test", List.of("tenant-admin"), false);

        svc.create(TENANT_ID, req, "alice");

        verify(keycloak).assignClientRoleToUser(REALM, USER_ID, CLIENT, "user-viewer");
        verify(keycloak).assignClientRoleToUser(REALM, USER_ID, CLIENT, "tenant-admin");
    }

    @Test
    void create_withExplicitUserViewerRole_assignsUserViewerOnce() {
        CreateUserRequest req = new CreateUserRequest(
            "bob@app1.test", "Bob", "Test", List.of("user-viewer"), false);

        svc.create(TENANT_ID, req, "alice");

        // De-duplication: even if caller explicitly passes user-viewer we
        // should still assign it exactly once.
        verify(keycloak, times(1)).assignClientRoleToUser(REALM, USER_ID, CLIENT, "user-viewer");
    }

    @Test
    void updateRoles_withEmptyDesiredSet_keepsUserViewer() {
        // Current state in KC: user has both user-viewer and tenant-admin.
        when(keycloak.getUserClientRoles(REALM, USER_ID, CLIENT))
            .thenReturn(new ArrayList<>(List.of("user-viewer", "tenant-admin")));

        svc.updateRoles(TENANT_ID, USER_ID, Set.of(), "alice");

        // tenant-admin should be removed, but user-viewer must NOT be removed.
        verify(keycloak).removeClientRoleFromUser(REALM, USER_ID, CLIENT, "tenant-admin");
        verify(keycloak, never()).removeClientRoleFromUser(REALM, USER_ID, CLIENT, "user-viewer");
    }

    @Test
    void updateRoles_withTenantAdminOnly_keepsUserViewer() {
        // Current state in KC: user has only user-viewer.
        when(keycloak.getUserClientRoles(REALM, USER_ID, CLIENT))
            .thenReturn(new ArrayList<>(List.of("user-viewer")));

        svc.updateRoles(TENANT_ID, USER_ID, Set.of("tenant-admin"), "alice");

        // Should add tenant-admin and NOT remove user-viewer (effective set
        // is {tenant-admin, user-viewer}).
        verify(keycloak).assignClientRoleToUser(REALM, USER_ID, CLIENT, "tenant-admin");
        verify(keycloak, never()).removeClientRoleFromUser(REALM, USER_ID, CLIENT, "user-viewer");
    }

    @Test
    void updateRoles_rejectsUnknownRole() {
        try {
            svc.updateRoles(TENANT_ID, USER_ID, Set.of("ghost-role"), "alice");
            throw new AssertionError("expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).contains("ghost-role");
        }
    }

    // ---- listWithRoles (slug-keyed) ----

    @org.junit.jupiter.api.Nested
    class ListWithRoles {
        private static final String SLUG = "app1";
        private static final String USER_A = "user-a";
        private static final String USER_B = "user-b";

        @BeforeEach
        void slugTenant() {
            Tenant t = mock(Tenant.class);
            when(t.getRealmName()).thenReturn(REALM);
            when(tenants.getBySlug(SLUG)).thenReturn(t);
        }

        @Test
        void roleFilter_returnsUsersFromRoleMembers_andJoinsRealmRoles() {
            UserRepresentation a = new UserRepresentation();
            a.setId(USER_A); a.setUsername("alice"); a.setEmail("alice@app1.test");
            UserRepresentation b = new UserRepresentation();
            b.setId(USER_B); b.setUsername("bob"); b.setEmail("bob@app1.test");
            when(keycloak.listUsersByRealmRole(REALM, "inspector", 0, 50))
                .thenReturn(List.of(a, b));
            when(keycloak.getUserClientRoles(REALM, USER_A, CLIENT))
                .thenReturn(List.of("user-viewer"));
            when(keycloak.getUserClientRoles(REALM, USER_B, CLIENT))
                .thenReturn(List.of("user-viewer"));
            when(keycloak.getUserRealmRoles(REALM, USER_A)).thenReturn(List.of("inspector"));
            when(keycloak.getUserRealmRoles(REALM, USER_B)).thenReturn(List.of("inspector"));

            var result = svc.listWithRoles(SLUG, "inspector", null, 0, 50, true);

            assertThat(result.items()).hasSize(2);
            assertThat(result.items().get(0).realmRoles()).containsExactly("inspector");
            assertThat(result.items().get(1).realmRoles()).containsExactly("inspector");
            // Default path (listUsers) MUST NOT be invoked when role filter is set.
            verify(keycloak, never()).listUsers(anyString(), any(), anyInt(), anyInt());
        }

        @Test
        void unknownRole_returnsEmptyList() {
            when(keycloak.listUsersByRealmRole(REALM, "nonexistent", 0, 50))
                .thenReturn(List.of());

            var result = svc.listWithRoles(SLUG, "nonexistent", null, 0, 50, true);

            assertThat(result.items()).isEmpty();
            assertThat(result.totalItems()).isZero();
        }

        @Test
        void noRoleFilter_usesDefaultListUsers_andJoinsRealmRoles() {
            UserRepresentation a = new UserRepresentation();
            a.setId(USER_A); a.setUsername("alice");
            when(keycloak.listUsers(REALM, null, 0, 50)).thenReturn(List.of(a));
            when(keycloak.countUsers(REALM, null)).thenReturn(1);
            when(keycloak.getUserClientRoles(REALM, USER_A, CLIENT))
                .thenReturn(List.of("user-viewer"));
            when(keycloak.getUserRealmRoles(REALM, USER_A)).thenReturn(List.of("customer"));

            var result = svc.listWithRoles(SLUG, null, null, 0, 50, true);

            assertThat(result.items()).hasSize(1);
            assertThat(result.items().get(0).realmRoles()).containsExactly("customer");
            assertThat(result.totalItems()).isEqualTo(1);
            verify(keycloak, never()).listUsersByRealmRole(anyString(), anyString(),
                anyInt(), anyInt());
        }

        @Test
        void includeRealmRolesFalse_skipsRealmRolesJoin() {
            UserRepresentation a = new UserRepresentation();
            a.setId(USER_A); a.setUsername("alice");
            when(keycloak.listUsers(REALM, null, 0, 50)).thenReturn(List.of(a));
            when(keycloak.countUsers(REALM, null)).thenReturn(1);
            when(keycloak.getUserClientRoles(REALM, USER_A, CLIENT))
                .thenReturn(List.of("user-viewer"));

            var result = svc.listWithRoles(SLUG, null, null, 0, 50, false);

            assertThat(result.items()).hasSize(1);
            assertThat(result.items().get(0).realmRoles()).isNull();
            verify(keycloak, never()).getUserRealmRoles(anyString(), anyString());
        }

        @Test
        void roleFilterWithSearch_filtersInMemoryByUsernameOrEmail() {
            UserRepresentation a = new UserRepresentation();
            a.setId(USER_A); a.setUsername("alice"); a.setEmail("alice@app1.test");
            UserRepresentation b = new UserRepresentation();
            b.setId(USER_B); b.setUsername("bob"); b.setEmail("bob@app1.test");
            when(keycloak.listUsersByRealmRole(REALM, "inspector", 0, 50))
                .thenReturn(List.of(a, b));
            when(keycloak.getUserClientRoles(REALM, USER_A, CLIENT))
                .thenReturn(List.of("user-viewer"));
            when(keycloak.getUserRealmRoles(REALM, USER_A))
                .thenReturn(List.of("inspector"));

            var result = svc.listWithRoles(SLUG, "inspector", "alice", 0, 50, true);

            assertThat(result.items()).hasSize(1);
            assertThat(result.items().get(0).id()).isEqualTo(USER_A);
        }
    }
}
