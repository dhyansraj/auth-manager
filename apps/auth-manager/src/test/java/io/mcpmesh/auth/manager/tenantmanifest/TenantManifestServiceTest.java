package io.mcpmesh.auth.manager.tenantmanifest;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.roles.PermissionDto;
import io.mcpmesh.auth.manager.roles.RoleDto;
import io.mcpmesh.auth.manager.roles.RolesService;
import io.mcpmesh.auth.manager.service.TenantService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TenantManifestService}. Mocks {@link RolesService}
 * and {@link TenantService} so we can focus on shape, sort order, and
 * field mapping.
 */
class TenantManifestServiceTest {

    private static final String SLUG = "safesound";
    private static final String REALM = "t-safesound";

    private RolesService rolesService;
    private TenantService tenants;
    private TenantManifestService service;

    @BeforeEach
    void setUp() {
        rolesService = mock(RolesService.class);
        tenants = mock(TenantService.class);
        service = new TenantManifestService(rolesService, tenants);

        Tenant tenant = new Tenant(SLUG, "Safe Sound", "system", null);
        tenant.markActive(REALM);
        when(tenants.getBySlug(eq(SLUG))).thenReturn(tenant);
    }

    @Test
    void generate_populatesMeta() {
        when(rolesService.listPermissions(eq(SLUG))).thenReturn(List.of());
        when(rolesService.list(eq(SLUG))).thenReturn(List.of());

        Instant before = Instant.now();
        TenantManifest m = service.generate(SLUG);
        Instant after = Instant.now();

        assertThat(m.meta().tenantSlug()).isEqualTo(SLUG);
        assertThat(m.meta().realmName()).isEqualTo(REALM);
        assertThat(m.meta().version()).isEqualTo("v1");
        assertThat(m.meta().generatedAt()).isBetween(before, after);
    }

    @Test
    void generate_mapsPermissions_andSortsById() {
        when(rolesService.listPermissions(eq(SLUG))).thenReturn(List.of(
            new PermissionDto("safesound-backend", "HOME_VIEW_OWN", "View homes the caller owns"),
            new PermissionDto("safesound-backend", "BOOKING_VIEW_OWN", "View bookings I created"),
            new PermissionDto("other-backend", "ALARM_RING", "Ring the alarm")
        ));
        when(rolesService.list(eq(SLUG))).thenReturn(List.of());

        TenantManifest m = service.generate(SLUG);

        assertThat(m.permissions()).extracting(TenantManifest.PermissionEntry::id)
            .containsExactly("ALARM_RING", "BOOKING_VIEW_OWN", "HOME_VIEW_OWN");

        TenantManifest.PermissionEntry first = m.permissions().get(0);
        assertThat(first.client()).isEqualTo("other-backend");
        assertThat(first.description()).isEqualTo("Ring the alarm");
    }

    @Test
    void generate_mapsRoles_andSortsByName_andSortsPermissionIds() {
        when(rolesService.listPermissions(eq(SLUG))).thenReturn(List.of());
        when(rolesService.list(eq(SLUG))).thenReturn(List.of(
            new RoleDto("provider", "Service provider",
                List.of(
                    new PermissionDto("safesound-backend", "HOME_VIEW_OWN"),
                    new PermissionDto("safesound-backend", "BOOKING_VIEW_OWN")
                ),
                3, false, false),
            new RoleDto("customer", "Default role for self-signup users",
                List.of(
                    new PermissionDto("safesound-backend", "BOOKING_VIEW_OWN"),
                    new PermissionDto("safesound-backend", "HOME_VIEW_OWN")
                ),
                17, false, false)
        ));

        TenantManifest m = service.generate(SLUG);

        assertThat(m.roles()).extracting(TenantManifest.RoleEntry::name)
            .containsExactly("customer", "provider");

        TenantManifest.RoleEntry customer = m.roles().get(0);
        assertThat(customer.description()).isEqualTo("Default role for self-signup users");
        assertThat(customer.permissions()).containsExactly("BOOKING_VIEW_OWN", "HOME_VIEW_OWN");

        TenantManifest.RoleEntry provider = m.roles().get(1);
        assertThat(provider.permissions()).containsExactly("BOOKING_VIEW_OWN", "HOME_VIEW_OWN");
    }

    @Test
    void generate_tolerates_nullPermissionsList_onRole() {
        when(rolesService.listPermissions(eq(SLUG))).thenReturn(List.of());
        when(rolesService.list(eq(SLUG))).thenReturn(List.of(
            new RoleDto("empty-role", "no perms", null, 0, false, false)
        ));

        TenantManifest m = service.generate(SLUG);
        assertThat(m.roles()).hasSize(1);
        assertThat(m.roles().get(0).permissions()).isEmpty();
    }
}
