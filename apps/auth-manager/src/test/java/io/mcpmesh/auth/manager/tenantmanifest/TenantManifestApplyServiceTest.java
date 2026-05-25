package io.mcpmesh.auth.manager.tenantmanifest;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.roles.CreateRoleRequest;
import io.mcpmesh.auth.manager.roles.RolesService;
import io.mcpmesh.auth.manager.roles.UpdateRoleRequest;
import io.mcpmesh.auth.manager.service.TenantService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TenantManifestApplyService}. The KC admin client and
 * {@link RolesService} are mocked so we can drive each diff branch without a
 * real Keycloak. {@link TenantManifestService} is wired with mocks behind it
 * so {@code generate(slug)} returns whatever "current KC state" the test sets.
 */
class TenantManifestApplyServiceTest {

    private static final String SLUG = "safesound";
    private static final String REALM = "t-safesound";
    private static final String CLIENT_ID = "safesound-backend";
    private static final String CLIENT_UUID = "client-uuid";

    private Keycloak admin;
    private TenantService tenants;
    private RolesService rolesService;
    private TenantManifestService manifestService;  // mocked: drives "current state"
    private RealmResource realm;
    private ClientsResource clientsResource;
    private ClientResource clientResource;
    private RolesResource clientRoles;

    private TenantManifestApplyService apply;

    @BeforeEach
    void setUp() {
        admin = mock(Keycloak.class);
        tenants = mock(TenantService.class);
        rolesService = mock(RolesService.class);
        manifestService = mock(TenantManifestService.class);
        realm = mock(RealmResource.class);
        clientsResource = mock(ClientsResource.class);
        clientResource = mock(ClientResource.class);
        clientRoles = mock(RolesResource.class);

        Tenant t = mock(Tenant.class);
        when(t.getRealmName()).thenReturn(REALM);
        when(tenants.getBySlug(SLUG)).thenReturn(t);

        when(admin.realm(REALM)).thenReturn(realm);
        when(realm.clients()).thenReturn(clientsResource);

        ClientRepresentation client = new ClientRepresentation();
        client.setId(CLIENT_UUID);
        client.setClientId(CLIENT_ID);
        when(clientsResource.findAll()).thenReturn(List.of(client));
        when(clientsResource.get(CLIENT_UUID)).thenReturn(clientResource);
        when(clientResource.roles()).thenReturn(clientRoles);

        // Default: realm has no stored hash and is empty.
        stubRealmAttributes(null);

        apply = new TenantManifestApplyService(admin, tenants, manifestService, rolesService);
    }

    // -------------------------------------------------------------------------
    // Permission diff
    // -------------------------------------------------------------------------

    @Test
    void apply_emptyIncomingAndCurrent_isNoOp() {
        stubCurrent(List.of(), List.of());

        ApplyResult result = apply.apply(SLUG, manifest(List.of(), List.of()),
            false, false, false, "alice");

        assertThat(result.dryRun()).isFalse();
        assertThat(result.permissions().created()).isEmpty();
        assertThat(result.permissions().updated()).isEmpty();
        assertThat(result.permissions().unchanged()).isEmpty();
        assertThat(result.permissions().skippedAsMissing()).isEmpty();
        assertThat(result.roles()).isNull();
        assertThat(result.hashTripwire()).isNull();
        assertThat(result.warnings()).isEmpty();

        verify(clientRoles, never()).create(any());
    }

    @Test
    void apply_newPermission_createsClientRole() {
        stubCurrent(List.of(), List.of());

        var incoming = manifest(List.of(
            new TenantManifest.PermissionEntry("HOME_VIEW", "View homes", CLIENT_ID)
        ), List.of());

        ApplyResult result = apply.apply(SLUG, incoming, false, false, false, "alice");

        assertThat(result.permissions().created()).containsExactly("HOME_VIEW");
        ArgumentCaptor<RoleRepresentation> captor = ArgumentCaptor.forClass(RoleRepresentation.class);
        verify(clientRoles, times(1)).create(captor.capture());
        assertThat(captor.getValue().getName()).isEqualTo("HOME_VIEW");
        assertThat(captor.getValue().getDescription()).isEqualTo("View homes");
    }

    @Test
    void apply_permissionInKcNotInManifest_skippedWithWarning_andNoMutation() {
        // KC has HOME_VIEW; incoming manifest is empty -> skip + warn, no delete.
        stubCurrent(List.of(
            new TenantManifest.PermissionEntry("HOME_VIEW", "View homes", CLIENT_ID)
        ), List.of());

        ApplyResult result = apply.apply(SLUG, manifest(List.of(), List.of()),
            false, false, false, "alice");

        assertThat(result.permissions().created()).isEmpty();
        assertThat(result.permissions().updated()).isEmpty();
        assertThat(result.permissions().skippedAsMissing()).containsExactly("HOME_VIEW");
        assertThat(result.warnings())
            .anyMatch(w -> w.contains("HOME_VIEW") && w.contains("left alone"));
        verify(clientRoles, never()).create(any());
    }

    @Test
    void apply_permissionDescriptionChanged_updates() {
        stubCurrent(List.of(
            new TenantManifest.PermissionEntry("HOME_VIEW", "old desc", CLIENT_ID)
        ), List.of());

        // Stub the get-then-update path for the existing role.
        RoleResource existingRr = mock(RoleResource.class);
        when(clientRoles.get("HOME_VIEW")).thenReturn(existingRr);
        RoleRepresentation existing = new RoleRepresentation();
        existing.setName("HOME_VIEW");
        existing.setDescription("old desc");
        when(existingRr.toRepresentation()).thenReturn(existing);

        var incoming = manifest(List.of(
            new TenantManifest.PermissionEntry("HOME_VIEW", "new desc", CLIENT_ID)
        ), List.of());

        ApplyResult result = apply.apply(SLUG, incoming, false, false, false, "alice");

        assertThat(result.permissions().updated()).containsExactly("HOME_VIEW");
        ArgumentCaptor<RoleRepresentation> captor = ArgumentCaptor.forClass(RoleRepresentation.class);
        verify(existingRr).update(captor.capture());
        assertThat(captor.getValue().getDescription()).isEqualTo("new desc");
    }

    // -------------------------------------------------------------------------
    // applyRoles=false: roles diff is null
    // -------------------------------------------------------------------------

    @Test
    void apply_applyRolesFalse_skipsRoleSection() {
        stubCurrent(List.of(), List.of(
            new TenantManifest.RoleEntry("customer", "old", List.of())
        ));

        var incoming = manifest(List.of(), List.of(
            new TenantManifest.RoleEntry("customer", "new", List.of())
        ));

        ApplyResult result = apply.apply(SLUG, incoming, false, false, false, "alice");

        assertThat(result.roles()).isNull();
        assertThat(result.hashTripwire()).isNull();
        verify(rolesService, never()).create(eq(SLUG), any(), any());
        verify(rolesService, never()).update(eq(SLUG), any(), any(), any());
    }

    // -------------------------------------------------------------------------
    // applyRoles=true, no stored hash, role differences
    // -------------------------------------------------------------------------

    @Test
    void apply_applyRolesTrue_noStoredHash_createsRoleAndStoresHash() {
        stubRealmAttributes(null);
        // After-apply snapshot will have the role; we drive that via stubCurrent
        // returning different snapshots on each invocation.
        TenantManifest currentBefore = manifest(List.of(
            new TenantManifest.PermissionEntry("HOME_VIEW", "v", CLIENT_ID)
        ), List.of());
        TenantManifest currentAfter = manifest(List.of(
            new TenantManifest.PermissionEntry("HOME_VIEW", "v", CLIENT_ID)
        ), List.of(
            new TenantManifest.RoleEntry("customer", "desc", List.of("HOME_VIEW"))
        ));
        when(manifestService.generate(SLUG)).thenReturn(currentBefore, currentAfter);

        var incoming = manifest(List.of(
            new TenantManifest.PermissionEntry("HOME_VIEW", "v", CLIENT_ID)
        ), List.of(
            new TenantManifest.RoleEntry("customer", "desc", List.of("HOME_VIEW"))
        ));

        ApplyResult result = apply.apply(SLUG, incoming, true, false, false, "alice");

        assertThat(result.roles()).isNotNull();
        assertThat(result.roles().created()).containsExactly("customer");
        assertThat(result.hashTripwire()).isNotNull();
        assertThat(result.hashTripwire().storedHash()).isNull();
        assertThat(result.hashTripwire().match()).isTrue();
        assertThat(result.hashTripwire().tripped()).isFalse();
        assertThat(result.hashTripwire().newHashAfterApply()).startsWith("sha256:");

        // RolesService.create called once for "customer".
        ArgumentCaptor<CreateRoleRequest> captor = ArgumentCaptor.forClass(CreateRoleRequest.class);
        verify(rolesService).create(eq(SLUG), captor.capture(), eq("alice"));
        assertThat(captor.getValue().name()).isEqualTo("customer");
        assertThat(captor.getValue().permissions()).hasSize(1);
        assertThat(captor.getValue().permissions().get(0).client()).isEqualTo(CLIENT_ID);
        assertThat(captor.getValue().permissions().get(0).name()).isEqualTo("HOME_VIEW");

        // Verify the realm was updated with the hash attribute.
        ArgumentCaptor<RealmRepresentation> realmCap = ArgumentCaptor.forClass(RealmRepresentation.class);
        verify(realm).update(realmCap.capture());
        assertThat(realmCap.getValue().getAttributes())
            .containsKey(TenantManifestApplyService.SEED_ROLES_HASH_ATTR);
    }

    // -------------------------------------------------------------------------
    // applyRoles=true, stored hash matches current
    // -------------------------------------------------------------------------

    @Test
    void apply_applyRolesTrue_storedHashMatches_updatesRoleAndRefreshesHash() {
        // current state: role "customer" with HOME_VIEW; we'll add ALARM_RING in the update.
        TenantManifest currentBefore = manifest(List.of(
            new TenantManifest.PermissionEntry("HOME_VIEW", "v", CLIENT_ID),
            new TenantManifest.PermissionEntry("ALARM_RING", "v", CLIENT_ID)
        ), List.of(
            new TenantManifest.RoleEntry("customer", "desc", List.of("HOME_VIEW"))
        ));
        String storedHash = apply.hashRoles(currentBefore.roles());
        stubRealmAttributes(storedHash);

        TenantManifest currentAfter = manifest(currentBefore.permissions(), List.of(
            new TenantManifest.RoleEntry("customer", "desc",
                List.of("HOME_VIEW", "ALARM_RING"))
        ));
        when(manifestService.generate(SLUG)).thenReturn(currentBefore, currentAfter);

        var incoming = manifest(currentBefore.permissions(), List.of(
            new TenantManifest.RoleEntry("customer", "desc",
                List.of("HOME_VIEW", "ALARM_RING"))
        ));

        ApplyResult result = apply.apply(SLUG, incoming, true, false, false, "alice");

        assertThat(result.roles().updated()).containsExactly("customer");
        assertThat(result.hashTripwire().match()).isTrue();
        assertThat(result.hashTripwire().tripped()).isFalse();
        assertThat(result.hashTripwire().newHashAfterApply()).isNotNull();
        assertThat(result.hashTripwire().newHashAfterApply()).isNotEqualTo(storedHash);

        verify(rolesService).update(eq(SLUG), eq("customer"), any(UpdateRoleRequest.class), eq("alice"));
    }

    // -------------------------------------------------------------------------
    // Tripwire: hash mismatch, force=false -> no mutations
    // -------------------------------------------------------------------------

    @Test
    void apply_applyRolesTrue_hashMismatch_noForce_throwsTripwireWithNoMutations() {
        TenantManifest current = manifest(List.of(), List.of(
            new TenantManifest.RoleEntry("customer", null, List.of())
        ));
        // Stored hash points to a different role set.
        TenantManifest staleStored = manifest(List.of(), List.of(
            new TenantManifest.RoleEntry("OLD_ROLE", null, List.of())
        ));
        String storedHash = apply.hashRoles(staleStored.roles());
        stubRealmAttributes(storedHash);
        stubCurrent(List.of(), current.roles());

        var incoming = manifest(List.of(), List.of(
            new TenantManifest.RoleEntry("customer", null, List.of()),
            new TenantManifest.RoleEntry("provider", null, List.of())
        ));

        assertThatThrownBy(() -> apply.apply(SLUG, incoming, true, false, false, "alice"))
            .isInstanceOf(TenantManifestApplyService.TripwireException.class)
            .satisfies(t -> {
                ApplyResult r = ((TenantManifestApplyService.TripwireException) t).result();
                assertThat(r.hashTripwire().tripped()).isTrue();
                assertThat(r.hashTripwire().match()).isFalse();
                assertThat(r.hashTripwire().newHashAfterApply()).isNull();
            });

        verify(rolesService, never()).create(eq(SLUG), any(), any());
        verify(rolesService, never()).update(eq(SLUG), any(), any(), any());
        verify(realm, never()).update(any(RealmRepresentation.class));
    }

    // -------------------------------------------------------------------------
    // Tripwire: hash mismatch + force=true -> proceeds, tripped=true in result
    // -------------------------------------------------------------------------

    @Test
    void apply_applyRolesTrue_hashMismatch_force_proceedsAndMarksTripped() {
        TenantManifest currentBefore = manifest(List.of(), List.of(
            new TenantManifest.RoleEntry("customer", null, List.of())
        ));
        TenantManifest staleStored = manifest(List.of(), List.of(
            new TenantManifest.RoleEntry("OLD_ROLE", null, List.of())
        ));
        String storedHash = apply.hashRoles(staleStored.roles());
        stubRealmAttributes(storedHash);

        TenantManifest currentAfter = manifest(List.of(), List.of(
            new TenantManifest.RoleEntry("customer", null, List.of()),
            new TenantManifest.RoleEntry("provider", null, List.of())
        ));
        when(manifestService.generate(SLUG)).thenReturn(currentBefore, currentAfter);

        var incoming = manifest(List.of(), List.of(
            new TenantManifest.RoleEntry("customer", null, List.of()),
            new TenantManifest.RoleEntry("provider", null, List.of())
        ));

        ApplyResult result = apply.apply(SLUG, incoming, true, true, false, "alice");

        assertThat(result.hashTripwire().tripped()).isTrue();
        assertThat(result.hashTripwire().match()).isFalse();
        assertThat(result.hashTripwire().newHashAfterApply()).isNotNull();
        assertThat(result.roles().created()).containsExactly("provider");
        verify(rolesService).create(eq(SLUG), any(), eq("alice"));
    }

    // -------------------------------------------------------------------------
    // dryRun
    // -------------------------------------------------------------------------

    @Test
    void apply_dryRun_computesDiffWithoutMutation() {
        stubCurrent(List.of(), List.of());

        var incoming = manifest(List.of(
            new TenantManifest.PermissionEntry("HOME_VIEW", "x", CLIENT_ID)
        ), List.of(
            new TenantManifest.RoleEntry("customer", null, List.of("HOME_VIEW"))
        ));

        ApplyResult result = apply.apply(SLUG, incoming, true, false, true, "alice");

        assertThat(result.dryRun()).isTrue();
        assertThat(result.permissions().created()).containsExactly("HOME_VIEW");
        assertThat(result.roles().created()).containsExactly("customer");
        assertThat(result.hashTripwire().newHashAfterApply()).isNull();

        verify(clientRoles, never()).create(any());
        verify(rolesService, never()).create(eq(SLUG), any(), any());
        verify(realm, never()).update(any(RealmRepresentation.class));
    }

    // -------------------------------------------------------------------------
    // Validation errors -> 400 semantics
    // -------------------------------------------------------------------------

    @Test
    void apply_permissionReferencesUnknownClient_throwsIllegalArgument() {
        stubCurrent(List.of(), List.of());

        var incoming = manifest(List.of(
            new TenantManifest.PermissionEntry("HOME_VIEW", "x", "no-such-client")
        ), List.of());

        assertThatThrownBy(() -> apply.apply(SLUG, incoming, false, false, false, "alice"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("no-such-client");
    }

    @Test
    void apply_roleReferencesUnknownPermission_throwsIllegalArgument() {
        stubCurrent(List.of(), List.of());

        var incoming = manifest(List.of(), List.of(
            new TenantManifest.RoleEntry("customer", null, List.of("GHOST_PERM"))
        ));

        assertThatThrownBy(() -> apply.apply(SLUG, incoming, true, false, false, "alice"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("GHOST_PERM");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void stubCurrent(List<TenantManifest.PermissionEntry> perms,
                             List<TenantManifest.RoleEntry> roles) {
        when(manifestService.generate(SLUG)).thenReturn(manifest(perms, roles));
    }

    private static TenantManifest manifest(List<TenantManifest.PermissionEntry> perms,
                                           List<TenantManifest.RoleEntry> roles) {
        return new TenantManifest(
            new TenantManifest.Meta(SLUG, REALM, Instant.parse("2026-05-23T10:30:00Z"), "v1"),
            new ArrayList<>(perms),
            new ArrayList<>(roles)
        );
    }

    /** Stub realm.toRepresentation() to return a rep whose attributes carry (or don't carry) the hash. */
    private void stubRealmAttributes(String storedHash) {
        Map<String, String> attrs = new HashMap<>();
        if (storedHash != null) attrs.put(TenantManifestApplyService.SEED_ROLES_HASH_ATTR, storedHash);
        RealmRepresentation rep = new RealmRepresentation();
        rep.setRealm(REALM);
        rep.setAttributes(attrs);
        when(realm.toRepresentation()).thenReturn(rep);
    }
}
