package io.mcpmesh.auth.manager.roles;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.IdentityProvidersBootstrap;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.service.TenantService;
import jakarta.ws.rs.NotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.RoleScopeResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RolesService}. Stubs the KC admin client so we don't
 * need a real KC server. Focuses on the visibility filter, composite diff
 * semantics, user-count guard, and permission-catalog client filtering.
 */
class RolesServiceTest {

    private static final String SLUG = "app1";
    private static final String REALM = "t-app1";
    private static final UUID TENANT_ID = UUID.randomUUID();
    private static final String ORDERS_CLIENT_UUID = "orders-uuid";
    private static final String INVOICES_CLIENT_UUID = "invoices-uuid";

    private Keycloak admin;
    private TenantService tenants;
    private AuditService audit;
    private KeycloakAdminService keycloak;
    private IdentityProvidersBootstrap identityProvidersBootstrap;
    private RealmResource realm;
    private RolesResource realmRoles;
    private ClientsResource clientsResource;

    private RolesService service;

    @BeforeEach
    void setUp() {
        admin = mock(Keycloak.class);
        tenants = mock(TenantService.class);
        audit = mock(AuditService.class);
        keycloak = mock(KeycloakAdminService.class);
        identityProvidersBootstrap = mock(IdentityProvidersBootstrap.class);
        realm = mock(RealmResource.class);
        realmRoles = mock(RolesResource.class);
        clientsResource = mock(ClientsResource.class);

        Tenant t = mock(Tenant.class);
        when(t.getRealmName()).thenReturn(REALM);
        when(t.getId()).thenReturn(TENANT_ID);
        when(tenants.getBySlug(SLUG)).thenReturn(t);

        when(admin.realm(REALM)).thenReturn(realm);
        when(realm.roles()).thenReturn(realmRoles);
        when(realm.clients()).thenReturn(clientsResource);

        // Default stubs for computeDefaultRoleNames: no default-roles composite
        // members + no enabled IdPs. Tests that need isDefault=true override
        // these per-test.
        when(identityProvidersBootstrap.listEnabledProviders(anyString())).thenReturn(Set.of());

        service = new RolesService(admin, tenants, audit, keycloak, identityProvidersBootstrap);
    }

    // ---- listPermissions filtering ----

    @Test
    void listPermissions_filtersSystemClientsAndUiClient_andDropsComposites() {
        // 4 clients total: orders (app), invoices (app), usermanagement (system), app1-ui (tenant UI)
        ClientRepresentation orders = client(ORDERS_CLIENT_UUID, "orders");
        ClientRepresentation invoices = client(INVOICES_CLIENT_UUID, "invoices");
        ClientRepresentation um = client("um-uuid", "usermanagement");
        ClientRepresentation ui = client("ui-uuid", "app1-ui");
        when(clientsResource.findAll()).thenReturn(List.of(orders, invoices, um, ui));

        // orders has order:view (atomic) + a composite (must be skipped)
        RolesResource ordersRoles = mock(RolesResource.class);
        ClientResource ordersCr = mock(ClientResource.class);
        when(clientsResource.get(ORDERS_CLIENT_UUID)).thenReturn(ordersCr);
        when(ordersCr.roles()).thenReturn(ordersRoles);
        when(ordersRoles.list()).thenReturn(List.of(
            atomicRole("order:view", "View orders"),
            atomicRole("order:approve", "Approve orders"),
            compositeRole("order:super", "composite skipped")
        ));

        // invoices has invoice:view
        RolesResource invoicesRoles = mock(RolesResource.class);
        ClientResource invoicesCr = mock(ClientResource.class);
        when(clientsResource.get(INVOICES_CLIENT_UUID)).thenReturn(invoicesCr);
        when(invoicesCr.roles()).thenReturn(invoicesRoles);
        when(invoicesRoles.list()).thenReturn(List.of(
            atomicRole("invoice:view", "View invoices")
        ));

        // Verify the system clients are never traversed.
        var result = service.listPermissions(SLUG);

        assertThat(result).extracting(PermissionDto::client, PermissionDto::name)
            .containsExactly(
                org.assertj.core.groups.Tuple.tuple("invoices", "invoice:view"),
                org.assertj.core.groups.Tuple.tuple("orders", "order:approve"),
                org.assertj.core.groups.Tuple.tuple("orders", "order:view")
            );
        verify(clientsResource, never()).get("um-uuid");
        verify(clientsResource, never()).get("ui-uuid");
    }

    // ---- list filtering ----

    @Test
    void list_filtersBuiltinsAndDefaultRolesAndReservedNamesAndSystemAttr() {
        when(clientsResource.findAll()).thenReturn(List.of());
        RoleRepresentation r1 = realmRole("Order Manager", "approves orders", false);
        RoleRepresentation r2 = realmRole("offline_access", null, false);      // builtin
        RoleRepresentation r3 = realmRole("uma_authorization", null, false);   // builtin
        RoleRepresentation r4 = realmRole("default-roles-" + REALM, null, false); // KC default
        RoleRepresentation r5 = realmRole("tenant-admin", null, false);        // reserved
        RoleRepresentation r6 = realmRole("_system-foo", null, false);         // system prefix
        RoleRepresentation r7 = realmRole("Hidden", null, true);               // system attr
        when(realmRoles.list()).thenReturn(List.of(r1, r2, r3, r4, r5, r6, r7));

        // For r1: stub the per-role lookups (composites + user count)
        RoleResource r1Resource = mock(RoleResource.class);
        when(realmRoles.get("Order Manager")).thenReturn(r1Resource);
        when(r1Resource.getRoleComposites()).thenReturn(Set.of());
        when(r1Resource.getRoleUserMembers()).thenReturn(Set.of(userRep("u1"), userRep("u2")));

        var out = service.list(SLUG);

        assertThat(out).hasSize(1);
        RoleDto only = out.get(0);
        assertThat(only.name()).isEqualTo("Order Manager");
        assertThat(only.description()).isEqualTo("approves orders");
        assertThat(only.permissions()).isEmpty();
        assertThat(only.userCount()).isEqualTo(2);
        assertThat(only.system()).isFalse();
    }

    @Test
    void list_marksRoleAsDefault_whenInDefaultRolesComposite() {
        when(clientsResource.findAll()).thenReturn(List.of());
        RoleRepresentation customer = realmRole("customer", "Auto-assigned at signup", false);
        when(realmRoles.list()).thenReturn(List.of(customer));

        // customer is visible; stub composites + user-count lookups
        RoleResource customerResource = mock(RoleResource.class);
        when(realmRoles.get("customer")).thenReturn(customerResource);
        when(customerResource.getRoleComposites()).thenReturn(Set.of());
        when(customerResource.getRoleUserMembers()).thenReturn(Set.of());

        // default-roles-<realm> composite includes "customer"
        RoleResource defaultRolesResource = mock(RoleResource.class);
        when(realmRoles.get("default-roles-" + REALM)).thenReturn(defaultRolesResource);
        RoleRepresentation customerRef = new RoleRepresentation();
        customerRef.setName("customer");
        when(defaultRolesResource.getRealmRoleComposites()).thenReturn(Set.of(customerRef));

        var out = service.list(SLUG);

        assertThat(out).hasSize(1);
        assertThat(out.get(0).name()).isEqualTo("customer");
        assertThat(out.get(0).isDefault()).isTrue();
    }

    // ---- create ----

    @Test
    void create_persistsRoleAndComposites() {
        // Role doesn't exist yet.
        RoleResource newR = mock(RoleResource.class);
        when(realmRoles.get("Order Manager")).thenReturn(newR);
        when(newR.toRepresentation())
            .thenThrow(new NotFoundException("missing"))     // create-time check
            .thenReturn(realmRole("Order Manager", "Approve orders", false))  // get(after)
            .thenReturn(realmRole("Order Manager", "Approve orders", false)); // any extra

        // After create: composites empty, user count zero. Stub composites lookup.
        when(newR.getRoleComposites()).thenReturn(Set.of());
        when(newR.getRoleUserMembers()).thenReturn(Set.of());

        // Permission ref resolution.
        ClientRepresentation orders = client(ORDERS_CLIENT_UUID, "orders");
        when(clientsResource.findAll()).thenReturn(List.of(orders));
        ClientResource ordersCr = mock(ClientResource.class);
        when(clientsResource.get(ORDERS_CLIENT_UUID)).thenReturn(ordersCr);
        RolesResource ordersRoles = mock(RolesResource.class);
        when(ordersCr.roles()).thenReturn(ordersRoles);
        RoleResource viewRr = mock(RoleResource.class);
        when(ordersRoles.get("order:view")).thenReturn(viewRr);
        RoleRepresentation viewRep = atomicRole("order:view", "View orders");
        viewRep.setContainerId(ORDERS_CLIENT_UUID);
        viewRep.setClientRole(true);
        when(viewRr.toRepresentation()).thenReturn(viewRep);

        var req = new CreateRoleRequest("Order Manager", "Approve orders",
            List.of(new CreateRoleRequest.PermissionRef("orders", "order:view")));

        var dto = service.create(SLUG, req, "alice");

        assertThat(dto.name()).isEqualTo("Order Manager");
        verify(realmRoles).create(any(RoleRepresentation.class));
        verify(newR).addComposites(anyList());
        verify(audit).recordSuccess(
            anyString(), any(), any(UUID.class),
            anyString(), anyString(), anyString(), any(), any());
    }

    @Test
    void create_rejectsReservedName() {
        var req = new CreateRoleRequest("tenant-admin", "x", List.of());
        assertThatThrownBy(() -> service.create(SLUG, req, "alice"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Reserved");
    }

    @Test
    void create_rejectsInvalidName() {
        var req = new CreateRoleRequest("bad/name!", "x", List.of());
        assertThatThrownBy(() -> service.create(SLUG, req, "alice"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Invalid role name");
    }

    @Test
    void create_rejectsDefaultRolesPrefix() {
        var req = new CreateRoleRequest("default-roles-foo", "x", List.of());
        assertThatThrownBy(() -> service.create(SLUG, req, "alice"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void create_rejectsUnknownClientInPermissions() {
        RoleResource newR = mock(RoleResource.class);
        when(realmRoles.get("MyRole")).thenReturn(newR);
        when(newR.toRepresentation()).thenThrow(new NotFoundException("missing"));
        when(clientsResource.findAll()).thenReturn(List.of()); // no clients

        var req = new CreateRoleRequest("MyRole", null,
            List.of(new CreateRoleRequest.PermissionRef("ghost", "x")));
        assertThatThrownBy(() -> service.create(SLUG, req, "alice"))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("Unknown client");
    }

    // ---- update with composite diff ----

    @Test
    void update_diffsCompositesAddingMissingAndRemovingExtra() {
        RoleResource rr = mock(RoleResource.class);
        when(realmRoles.get("Order Manager")).thenReturn(rr);
        RoleRepresentation existing = realmRole("Order Manager", "old", false);
        when(rr.toRepresentation()).thenReturn(existing);

        // Currently has order:view; we want order:approve only.
        ClientRepresentation orders = client(ORDERS_CLIENT_UUID, "orders");
        when(clientsResource.findAll()).thenReturn(List.of(orders));
        ClientResource ordersCr = mock(ClientResource.class);
        when(clientsResource.get(ORDERS_CLIENT_UUID)).thenReturn(ordersCr);
        RolesResource ordersRoles = mock(RolesResource.class);
        when(ordersCr.roles()).thenReturn(ordersRoles);

        RoleRepresentation viewComp = atomicRole("order:view", "View");
        viewComp.setContainerId(ORDERS_CLIENT_UUID);
        viewComp.setClientRole(true);
        RoleRepresentation approveComp = atomicRole("order:approve", "Approve");
        approveComp.setContainerId(ORDERS_CLIENT_UUID);
        approveComp.setClientRole(true);

        when(rr.getRoleComposites()).thenReturn(Set.of(viewComp));
        when(rr.getRoleUserMembers()).thenReturn(Set.of());

        RoleResource approveRr = mock(RoleResource.class);
        when(ordersRoles.get("order:approve")).thenReturn(approveRr);
        when(approveRr.toRepresentation()).thenReturn(approveComp);

        var req = new UpdateRoleRequest("new description",
            List.of(new CreateRoleRequest.PermissionRef("orders", "order:approve")));

        service.update(SLUG, "Order Manager", req, "alice");

        verify(rr).update(any(RoleRepresentation.class));
        verify(rr, times(1)).deleteComposites(anyList());
        verify(rr, times(1)).addComposites(anyList());
    }

    @Test
    void update_rejectsUnknownRole() {
        RoleResource rr = mock(RoleResource.class);
        when(realmRoles.get("Ghost")).thenReturn(rr);
        when(rr.toRepresentation()).thenThrow(new NotFoundException("nope"));

        var req = new UpdateRoleRequest("x", List.of());
        assertThatThrownBy(() -> service.update(SLUG, "Ghost", req, "alice"))
            .isInstanceOf(RoleNotFoundException.class);
    }

    // ---- delete ----

    @Test
    void delete_succeeds_whenNoUsersAssigned() {
        RoleResource rr = mock(RoleResource.class);
        when(realmRoles.get("Order Manager")).thenReturn(rr);
        when(rr.toRepresentation()).thenReturn(realmRole("Order Manager", "x", false));
        when(rr.getRoleUserMembers()).thenReturn(Set.of());

        service.delete(SLUG, "Order Manager", "alice");

        verify(realmRoles).deleteRole("Order Manager");
    }

    @Test
    void delete_throwsRoleInUse_whenUsersAssigned() {
        RoleResource rr = mock(RoleResource.class);
        when(realmRoles.get("Order Manager")).thenReturn(rr);
        when(rr.toRepresentation()).thenReturn(realmRole("Order Manager", "x", false));
        when(rr.getRoleUserMembers()).thenReturn(Set.of(userRep("u1"), userRep("u2"), userRep("u3")));

        assertThatThrownBy(() -> service.delete(SLUG, "Order Manager", "alice"))
            .isInstanceOf(RoleInUseException.class)
            .hasMessageContaining("3");
        verify(realmRoles, never()).deleteRole(anyString());
    }

    @Test
    void delete_rejects_unknownOrSystemRole() {
        RoleResource rr = mock(RoleResource.class);
        when(realmRoles.get("Ghost")).thenReturn(rr);
        when(rr.toRepresentation()).thenThrow(new NotFoundException("nope"));

        assertThatThrownBy(() -> service.delete(SLUG, "Ghost", "alice"))
            .isInstanceOf(RoleNotFoundException.class);
    }

    // ---- updateUserRoles ----

    @Test
    void updateUserRoles_appliesDiff_andIgnoresSystemRolesAlreadyOnUser() {
        // Visible roles in realm: "Manager", "Viewer". Plus system bits we must ignore.
        when(clientsResource.findAll()).thenReturn(List.of());
        RoleRepresentation manager = realmRole("Manager", null, false);
        RoleRepresentation viewer = realmRole("Viewer", null, false);
        RoleRepresentation builtin = realmRole("offline_access", null, false);
        RoleRepresentation defaults = realmRole("default-roles-" + REALM, null, false);
        when(realmRoles.list()).thenReturn(List.of(manager, viewer, builtin, defaults));

        // User has Viewer + offline_access. Desired = Manager only.
        UsersResource users = mock(UsersResource.class);
        when(realm.users()).thenReturn(users);
        UserResource userRes = mock(UserResource.class);
        when(users.get("user-1")).thenReturn(userRes);
        RoleMappingResource mappings = mock(RoleMappingResource.class);
        RoleScopeResource scope = mock(RoleScopeResource.class);
        when(userRes.roles()).thenReturn(mappings);
        when(mappings.realmLevel()).thenReturn(scope);
        when(scope.listAll()).thenReturn(List.of(viewer, builtin));

        var result = service.updateUserRoles(SLUG, "user-1", List.of("Manager"), "alice");

        assertThat(result.added()).containsExactly("Manager");
        assertThat(result.removed()).containsExactly("Viewer");
        // Verify we never touched offline_access.
        verify(scope, times(1)).remove(argThatContainsOnly("Viewer"));
        verify(scope, times(1)).add(argThatContainsOnly("Manager"));
    }

    @Test
    void updateUserRoles_rejectsUnknownRole() {
        when(clientsResource.findAll()).thenReturn(List.of());
        when(realmRoles.list()).thenReturn(List.of(realmRole("Manager", null, false)));

        UsersResource users = mock(UsersResource.class);
        when(realm.users()).thenReturn(users);

        assertThatThrownBy(() -> service.updateUserRoles(SLUG, "user-1", List.of("Ghost"), "alice"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Ghost");
    }

    @Test
    void updateUserRoles_rejectsSystemRoleByName() {
        when(clientsResource.findAll()).thenReturn(List.of());
        // tenant-admin is reserved, not visible -> caller can't assign it via this surface.
        when(realmRoles.list()).thenReturn(List.of(
            realmRole("Manager", null, false),
            realmRole("tenant-admin", null, false)
        ));

        UsersResource users = mock(UsersResource.class);
        when(realm.users()).thenReturn(users);

        assertThatThrownBy(() ->
            service.updateUserRoles(SLUG, "user-1", List.of("tenant-admin"), "alice"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("tenant-admin");
    }

    // ---- updateUserSystemRoles ----

    @Test
    void updateUserSystemRoles_addsTenantUserManager_andPreservesUserViewer() {
        // Current: just baseline user-viewer. Desired: + tenant-user-manager.
        when(keycloak.getUserClientRoles(REALM, "user-1", "usermanagement"))
            .thenReturn(new ArrayList<>(List.of("user-viewer")));

        var result = service.updateUserSystemRoles(SLUG, "user-1",
            List.of("tenant-user-manager"), "alice");

        assertThat(result.added()).containsExactly("tenant-user-manager");
        assertThat(result.removed()).isEmpty();
        verify(keycloak).assignClientRoleToUser(REALM, "user-1", "usermanagement", "tenant-user-manager");
        // user-viewer must NOT be removed even though caller didn't send it.
        verify(keycloak, never()).removeClientRoleFromUser(REALM, "user-1", "usermanagement", "user-viewer");
    }

    @Test
    void updateUserSystemRoles_emptyList_clearsManageableButKeepsUserViewer() {
        // Current: user-viewer + tenant-admin. Desired: clear all (empty list).
        when(keycloak.getUserClientRoles(REALM, "user-1", "usermanagement"))
            .thenReturn(new ArrayList<>(List.of("user-viewer", "tenant-admin")));

        var result = service.updateUserSystemRoles(SLUG, "user-1", List.of(), "alice");

        assertThat(result.added()).isEmpty();
        assertThat(result.removed()).containsExactly("tenant-admin");
        verify(keycloak).removeClientRoleFromUser(REALM, "user-1", "usermanagement", "tenant-admin");
        verify(keycloak, never()).removeClientRoleFromUser(REALM, "user-1", "usermanagement", "user-viewer");
    }

    @Test
    void updateUserSystemRoles_bothRoles_setsBoth_noExclusivityEnforcement() {
        // Backend permits the combo; the UI hints exclusivity but the API
        // doesn't enforce it.
        when(keycloak.getUserClientRoles(REALM, "user-1", "usermanagement"))
            .thenReturn(new ArrayList<>(List.of("user-viewer")));

        var result = service.updateUserSystemRoles(SLUG, "user-1",
            List.of("tenant-admin", "tenant-user-manager"), "alice");

        assertThat(result.added()).containsExactlyInAnyOrder("tenant-admin", "tenant-user-manager");
        assertThat(result.removed()).isEmpty();
        verify(keycloak).assignClientRoleToUser(REALM, "user-1", "usermanagement", "tenant-admin");
        verify(keycloak).assignClientRoleToUser(REALM, "user-1", "usermanagement", "tenant-user-manager");
    }

    @Test
    void updateUserSystemRoles_unrecognizedRole_throws400() {
        // No KC call should happen — we reject before touching KC.
        assertThatThrownBy(() ->
            service.updateUserSystemRoles(SLUG, "user-1", List.of("realm-admin"), "alice"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("realm-admin");
        verify(keycloak, never()).assignClientRoleToUser(anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void updateUserSystemRoles_explicitUserViewerSilentlyDropped() {
        // Caller sending user-viewer alongside a managed role should not 400
        // and should not produce a duplicate add (we silently re-add it
        // because it's the baseline).
        when(keycloak.getUserClientRoles(REALM, "user-1", "usermanagement"))
            .thenReturn(new ArrayList<>(List.of("user-viewer")));

        service.updateUserSystemRoles(SLUG, "user-1",
            List.of("user-viewer", "tenant-admin"), "alice");

        verify(keycloak).assignClientRoleToUser(REALM, "user-1", "usermanagement", "tenant-admin");
        verify(keycloak, never()).assignClientRoleToUser(REALM, "user-1", "usermanagement", "user-viewer");
    }

    @Test
    void updateUserSystemRoles_doesNotTouchOutOfScopeClientRoles() {
        // KC says the user holds some unrelated client role on usermanagement
        // (e.g. left over from earlier provisioning). The updater must leave
        // it alone — it's outside the manageable scope.
        when(keycloak.getUserClientRoles(REALM, "user-1", "usermanagement"))
            .thenReturn(new ArrayList<>(List.of("user-viewer", "some-other-role")));

        service.updateUserSystemRoles(SLUG, "user-1",
            List.of("tenant-admin"), "alice");

        verify(keycloak).assignClientRoleToUser(REALM, "user-1", "usermanagement", "tenant-admin");
        verify(keycloak, never()).removeClientRoleFromUser(REALM, "user-1", "usermanagement", "some-other-role");
    }

    // ---- helpers ----

    private static List<RoleRepresentation> argThatContainsOnly(String name) {
        return org.mockito.ArgumentMatchers.argThat(list ->
            list != null && list.size() == 1 && name.equals(list.get(0).getName()));
    }

    private static ClientRepresentation client(String uuid, String clientId) {
        ClientRepresentation c = new ClientRepresentation();
        c.setId(uuid);
        c.setClientId(clientId);
        return c;
    }

    private static RoleRepresentation atomicRole(String name, String desc) {
        RoleRepresentation r = new RoleRepresentation();
        r.setName(name);
        r.setDescription(desc);
        r.setComposite(false);
        return r;
    }

    private static RoleRepresentation compositeRole(String name, String desc) {
        RoleRepresentation r = new RoleRepresentation();
        r.setName(name);
        r.setDescription(desc);
        r.setComposite(true);
        return r;
    }

    private static RoleRepresentation realmRole(String name, String desc, boolean systemAttr) {
        RoleRepresentation r = new RoleRepresentation();
        r.setName(name);
        r.setDescription(desc);
        r.setComposite(true);
        if (systemAttr) {
            Map<String, List<String>> attrs = new HashMap<>();
            attrs.put("system", List.of("true"));
            r.setAttributes(attrs);
        }
        return r;
    }

    private static UserRepresentation userRep(String id) {
        UserRepresentation u = new UserRepresentation();
        u.setId(id);
        u.setUsername(id);
        return u;
    }
}
