package io.mcpmesh.auth.manager.service;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link PlatformPermissions} -- the atomic-permission catalog
 * consumed by admin-ui and materialized into Keycloak by the bootstrap classes.
 *
 * <p>These assertions are intentionally tight: the bundle structure is a
 * contract the admin-ui depends on, so any drift should fail loudly here
 * before reaching a deployment.
 */
class PlatformPermissionsTest {

    @Test
    void tenantBasePerms_containsOnlyTenantView() {
        assertThat(PlatformPermissions.TENANT_BASE_PERMS)
            .containsExactly("TENANT_VIEW");
    }

    @Test
    void tenantConfigPerms_doesNotIncludeTenantView() {
        // TENANT_VIEW moved out of TENANT_CONFIG_PERMS so tenant-user-manager
        // can also have it via TENANT_BASE_PERMS.
        assertThat(PlatformPermissions.TENANT_CONFIG_PERMS)
            .doesNotContain("TENANT_VIEW")
            .contains("TENANT_EDIT", "ROUTES_EDIT", "IDP_EDIT", "BRANDING_EDIT",
                      "PERMISSIONS_EDIT", "ROLES_EDIT", "APPS_EDIT", "MANIFEST_APPLY");
    }

    @Test
    void tenantAdminBundle_includesBaseConfigUserMgmtAndSystemRole() {
        // Admin gets everything: base + config + user-mgmt + system-role.
        assertThat(PlatformPermissions.TENANT_ADMIN_BUNDLE)
            .containsAll(PlatformPermissions.TENANT_BASE_PERMS)
            .containsAll(PlatformPermissions.TENANT_CONFIG_PERMS)
            .containsAll(PlatformPermissions.TENANT_USER_MGMT_PERMS)
            .contains(PlatformPermissions.TENANT_SYSTEM_ROLE_PERM)
            .contains("TENANT_VIEW");
    }

    @Test
    void tenantUserManagerBundle_includesBaseAndUserMgmtButNotConfig() {
        // tenant-user-manager: base (TENANT_VIEW) + user-mgmt; NO config, NO system-role.
        assertThat(PlatformPermissions.TENANT_USER_MANAGER_BUNDLE)
            .contains("TENANT_VIEW")
            .containsAll(PlatformPermissions.TENANT_USER_MGMT_PERMS)
            .doesNotContain("TENANT_EDIT", "ROUTES_EDIT", "IDP_EDIT", "BRANDING_EDIT",
                            "PERMISSIONS_EDIT", "ROLES_EDIT", "APPS_EDIT", "MANIFEST_APPLY")
            .doesNotContain(PlatformPermissions.TENANT_SYSTEM_ROLE_PERM);
    }

    @Test
    void allKnownPerms_includesEveryAtomicPermAcrossPlatformAndTenant() {
        // Sanity: the JWT-filter set must include all platform + tenant atomic
        // perms so MeController doesn't accidentally drop one.
        assertThat(PlatformPermissions.ALL_KNOWN_PERMS)
            .containsAll(PlatformPermissions.PLATFORM_PERMS)
            .containsAll(PlatformPermissions.TENANT_BASE_PERMS)
            .containsAll(PlatformPermissions.TENANT_CONFIG_PERMS)
            .containsAll(PlatformPermissions.TENANT_USER_MGMT_PERMS)
            .contains(PlatformPermissions.TENANT_SYSTEM_ROLE_PERM);
    }

    @Test
    void allTenantPerms_equalsTenantAdminBundle() {
        // ALL_TENANT_PERMS is what we materialize on every tenant realm's
        // usermanagement client; it should be the full admin bundle.
        assertThat(PlatformPermissions.ALL_TENANT_PERMS)
            .isEqualTo(PlatformPermissions.TENANT_ADMIN_BUNDLE);
    }
}
