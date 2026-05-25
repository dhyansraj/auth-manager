package io.mcpmesh.auth.manager.security;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.KeycloakProperties;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.service.TenantService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.net.URL;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TenantSecurity}, focusing on the platform-admin
 * bypass and the per-tenant role check fallback.
 */
class TenantSecurityTest {

    private static final String KC_URL = "http://localhost:8180";
    private static final String PLATFORM_REALM = "dev";
    private static final String PLATFORM_ROLE = "platform-admin";
    private static final String TENANT_REALM = "acme";
    private static final String TENANT_SLUG = "acme";
    private static final UUID TENANT_ID = UUID.randomUUID();

    // Conventional tenant-realm form used by the realm-name-derived current-tenant check.
    private static final String APP1_SLUG = "app1";
    private static final String APP1_REALM = "t-app1";
    private static final UUID APP1_ID = UUID.randomUUID();
    private static final String APP2_SLUG = "app2";
    private static final String APP2_REALM = "t-app2";
    private static final UUID APP2_ID = UUID.randomUUID();

    private TenantService tenants;
    private TenantRepository tenantRepository;
    private KeycloakProperties props;
    private TenantSecurity tenantSecurity;

    @BeforeEach
    void setUp() {
        tenants = mock(TenantService.class);
        tenantRepository = mock(TenantRepository.class);
        props = new KeycloakProperties(
            KC_URL, "master",
            new KeycloakProperties.Admin("admin-cli", "admin", "admin"),
            new KeycloakProperties.Platform(PLATFORM_REALM, PLATFORM_ROLE, null),
            null, null
        );
        tenantSecurity = new TenantSecurity(tenants, tenantRepository, props);

        Tenant tenant = mock(Tenant.class);
        when(tenant.getRealmName()).thenReturn(TENANT_REALM);
        when(tenants.get(TENANT_ID)).thenReturn(tenant);
        when(tenants.getBySlug(TENANT_SLUG)).thenReturn(tenant);

        Tenant app1 = mock(Tenant.class);
        when(app1.getId()).thenReturn(APP1_ID);
        when(app1.getRealmName()).thenReturn(APP1_REALM);
        when(app1.getSlug()).thenReturn(APP1_SLUG);
        when(tenantRepository.findByRealmNameAndDeletedAtIsNull(APP1_REALM))
            .thenReturn(Optional.of(app1));
        when(tenantRepository.findBySlugAndDeletedAtIsNull(APP1_SLUG))
            .thenReturn(Optional.of(app1));
        when(tenants.getBySlug(APP1_SLUG)).thenReturn(app1);

        Tenant app2 = mock(Tenant.class);
        when(app2.getId()).thenReturn(APP2_ID);
        when(app2.getRealmName()).thenReturn(APP2_REALM);
        when(app2.getSlug()).thenReturn(APP2_SLUG);
        when(tenantRepository.findByRealmNameAndDeletedAtIsNull(APP2_REALM))
            .thenReturn(Optional.of(app2));
        when(tenantRepository.findBySlugAndDeletedAtIsNull(APP2_SLUG))
            .thenReturn(Optional.of(app2));
        when(tenants.getBySlug(APP2_SLUG)).thenReturn(app2);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void hasRole_returnsFalse_whenNoJwtInContext() {
        SecurityContextHolder.getContext().setAuthentication(
            new AnonymousAuthenticationToken("k", "anon",
                List.of(new SimpleGrantedAuthority("ROLE_ANON"))));
        assertThat(tenantSecurity.hasRole(TENANT_ID, "tenant-admin")).isFalse();
    }

    @Test
    void hasRoleBySlug_returnsFalse_whenNoJwtInContext() {
        SecurityContextHolder.getContext().setAuthentication(
            new AnonymousAuthenticationToken("k", "anon",
                List.of(new SimpleGrantedAuthority("ROLE_ANON"))));
        assertThat(tenantSecurity.hasRoleBySlug(TENANT_SLUG, "tenant-admin")).isFalse();
    }

    @Test
    void hasRole_returnsTrue_whenPlatformAdminBypass() {
        setContext(jwtFromPlatformRealmWithRoles(List.of(PLATFORM_ROLE)));
        // NOTE: tenant realm doesn't matter, no resource_access on the JWT
        assertThat(tenantSecurity.hasRole(TENANT_ID, "tenant-admin")).isTrue();
    }

    @Test
    void hasRoleBySlug_returnsTrue_whenPlatformAdminBypass() {
        setContext(jwtFromPlatformRealmWithRoles(List.of(PLATFORM_ROLE)));
        assertThat(tenantSecurity.hasRoleBySlug(TENANT_SLUG, "tenant-admin")).isTrue();
    }

    @Test
    void hasRole_doesNotBypass_whenIssuerIsNotPlatformRealm() {
        // Issuer is a non-platform realm — must NOT bypass even if role present.
        Jwt jwt = jwt(
            KC_URL + "/realms/some-other-realm",
            Map.of("realm_access", Map.of("roles", List.of(PLATFORM_ROLE))),
            null
        );
        setContext(jwt);
        // Without platform bypass, this falls through to per-tenant check.
        // No resource_access claim => false.
        assertThat(tenantSecurity.hasRole(TENANT_ID, "tenant-admin")).isFalse();
    }

    @Test
    void hasRole_doesNotBypass_whenPlatformRoleMissing() {
        Jwt jwt = jwt(
            KC_URL + "/realms/" + PLATFORM_REALM,
            Map.of("realm_access", Map.of("roles", List.of("some-other-role"))),
            null
        );
        setContext(jwt);
        assertThat(tenantSecurity.hasRole(TENANT_ID, "tenant-admin")).isFalse();
    }

    @Test
    void hasRole_doesNotBypass_whenRealmAccessMissing() {
        Jwt jwt = jwt(
            KC_URL + "/realms/" + PLATFORM_REALM,
            Map.of(),
            null
        );
        setContext(jwt);
        assertThat(tenantSecurity.hasRole(TENANT_ID, "tenant-admin")).isFalse();
    }

    @Test
    void hasRole_returnsTrue_viaPerTenantClientRoleClaim_whenNotPlatformAdmin() {
        // Per-tenant fallback: caller has the tenant-admin client role on the
        // usermanagement client AND the JWT issuer matches the tenant realm.
        Jwt jwt = jwt(
            KC_URL + "/realms/" + TENANT_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("tenant-admin"))
            )),
            null
        );
        setContext(jwt);
        assertThat(tenantSecurity.hasRole(TENANT_ID, "tenant-admin")).isTrue();
    }

    // ----- currentTenantId / canSeeTenant ------------------------------------

    @Test
    void currentTenantId_returnsEmpty_whenNoJwt() {
        assertThat(tenantSecurity.currentTenantId()).isEmpty();
    }

    @Test
    void currentTenantId_returnsEmpty_whenIssuerLacksTenantRealmPrefix() {
        // Issuer's realm is "dev" — not a tenant realm (doesn't start with "t-").
        Jwt jwt = jwt(
            KC_URL + "/realms/" + PLATFORM_REALM,
            Map.of("realm_access", Map.of("roles", List.of(PLATFORM_ROLE))),
            null
        );
        setContext(jwt);
        assertThat(tenantSecurity.currentTenantId()).isEmpty();
    }

    @Test
    void currentTenantId_returnsTenantId_whenIssuerIsTenantRealm() {
        Jwt jwt = jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of(),
            null
        );
        setContext(jwt);
        assertThat(tenantSecurity.currentTenantId()).contains(APP1_ID);
    }

    @Test
    void currentTenantId_returnsEmpty_whenTenantRealmIsUnknown() {
        // realm starts with t- but no DB row maps to it (orphan/stale token).
        Jwt jwt = jwt(
            KC_URL + "/realms/t-orphan",
            Map.of(),
            null
        );
        setContext(jwt);
        when(tenantRepository.findByRealmNameAndDeletedAtIsNull("t-orphan"))
            .thenReturn(Optional.empty());
        assertThat(tenantSecurity.currentTenantId()).isEmpty();
    }

    @Test
    void canSeeTenant_isTrue_forPlatformAdmin_onAnyTenant() {
        setContext(jwtFromPlatformRealmWithRoles(List.of(PLATFORM_ROLE)));
        assertThat(tenantSecurity.canSeeTenant(APP1_ID)).isTrue();
        assertThat(tenantSecurity.canSeeTenant(APP2_ID)).isTrue();
        assertThat(tenantSecurity.canSeeTenant(UUID.randomUUID())).isTrue();
    }

    @Test
    void canSeeTenant_isTrue_forTenantAdminOfThatTenant() {
        Jwt jwt = jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of(),
            null
        );
        setContext(jwt);
        assertThat(tenantSecurity.canSeeTenant(APP1_ID)).isTrue();
    }

    @Test
    void canSeeTenant_isFalse_forTenantAdminOfDifferentTenant() {
        // Alice from app1 trying to fetch app2.
        Jwt jwt = jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of(),
            null
        );
        setContext(jwt);
        assertThat(tenantSecurity.canSeeTenant(APP2_ID)).isFalse();
    }

    @Test
    void canSeeTenant_isFalse_whenNoJwt() {
        assertThat(tenantSecurity.canSeeTenant(APP1_ID)).isFalse();
    }

    @Test
    void canSeeTenantBySlug_isTrue_forPlatformAdmin() {
        setContext(jwtFromPlatformRealmWithRoles(List.of(PLATFORM_ROLE)));
        assertThat(tenantSecurity.canSeeTenantBySlug(APP1_SLUG)).isTrue();
        // Platform admin doesn't need a DB row to "see" — we short-circuit.
        assertThat(tenantSecurity.canSeeTenantBySlug("does-not-exist")).isTrue();
    }

    @Test
    void canSeeTenantBySlug_isTrue_forTenantAdminOfThatSlug() {
        Jwt jwt = jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of(),
            null
        );
        setContext(jwt);
        assertThat(tenantSecurity.canSeeTenantBySlug(APP1_SLUG)).isTrue();
    }

    @Test
    void canSeeTenantBySlug_isFalse_forTenantAdminOfDifferentSlug() {
        Jwt jwt = jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of(),
            null
        );
        setContext(jwt);
        assertThat(tenantSecurity.canSeeTenantBySlug(APP2_SLUG)).isFalse();
    }

    @Test
    void canSeeTenantBySlug_isFalse_forMissingTenant() {
        Jwt jwt = jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of(),
            null
        );
        setContext(jwt);
        when(tenantRepository.findBySlugAndDeletedAtIsNull("does-not-exist"))
            .thenReturn(Optional.empty());
        assertThat(tenantSecurity.canSeeTenantBySlug("does-not-exist")).isFalse();
    }

    @Test
    void isPlatformAdmin_isFalse_whenNoJwt() {
        assertThat(tenantSecurity.isPlatformAdmin()).isFalse();
    }

    @Test
    void isPlatformAdmin_isTrue_forPlatformRealmCallerWithRole() {
        setContext(jwtFromPlatformRealmWithRoles(List.of(PLATFORM_ROLE)));
        assertThat(tenantSecurity.isPlatformAdmin()).isTrue();
    }

    // ----- canManageUsersInTenant(slug) -------------------------------------

    @Test
    void canManageUsersInTenant_isTrue_forPlatformAdmin() {
        setContext(jwtFromPlatformRealmWithRoles(List.of(PLATFORM_ROLE)));
        assertThat(tenantSecurity.canManageUsersInTenant(APP1_SLUG)).isTrue();
    }

    @Test
    void canManageUsersInTenant_isTrue_forTenantAdmin() {
        Jwt jwt = jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("tenant-admin"))
            )),
            null
        );
        setContext(jwt);
        assertThat(tenantSecurity.canManageUsersInTenant(APP1_SLUG)).isTrue();
    }

    @Test
    void canManageUsersInTenant_isTrue_forTenantUserManager() {
        Jwt jwt = jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("tenant-user-manager"))
            )),
            null
        );
        setContext(jwt);
        assertThat(tenantSecurity.canManageUsersInTenant(APP1_SLUG)).isTrue();
    }

    @Test
    void canManageUsersInTenant_isFalse_whenNeitherRolePresent() {
        // Caller is a plain user-viewer in the right realm: no manage rights.
        Jwt jwt = jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("user-viewer"))
            )),
            null
        );
        setContext(jwt);
        assertThat(tenantSecurity.canManageUsersInTenant(APP1_SLUG)).isFalse();
    }

    @Test
    void canManageUsersInTenant_isFalse_forTenantUserManagerOfDifferentTenant() {
        // Caller is tenant-user-manager in app1 but asking about app2.
        Jwt jwt = jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("tenant-user-manager"))
            )),
            null
        );
        setContext(jwt);
        assertThat(tenantSecurity.canManageUsersInTenant(APP2_SLUG)).isFalse();
    }

    // ----- canManageUsersInTenantId(uuid) -----------------------------------

    @Test
    void canManageUsersInTenantId_isTrue_forPlatformAdmin() {
        setContext(jwtFromPlatformRealmWithRoles(List.of(PLATFORM_ROLE)));
        assertThat(tenantSecurity.canManageUsersInTenantId(TENANT_ID)).isTrue();
    }

    @Test
    void canManageUsersInTenantId_isTrue_forTenantAdmin() {
        Jwt jwt = jwt(
            KC_URL + "/realms/" + TENANT_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("tenant-admin"))
            )),
            null
        );
        setContext(jwt);
        assertThat(tenantSecurity.canManageUsersInTenantId(TENANT_ID)).isTrue();
    }

    @Test
    void canManageUsersInTenantId_isTrue_forTenantUserManager() {
        Jwt jwt = jwt(
            KC_URL + "/realms/" + TENANT_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("tenant-user-manager"))
            )),
            null
        );
        setContext(jwt);
        assertThat(tenantSecurity.canManageUsersInTenantId(TENANT_ID)).isTrue();
    }

    @Test
    void canManageUsersInTenantId_isFalse_whenNeitherRolePresent() {
        Jwt jwt = jwt(
            KC_URL + "/realms/" + TENANT_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("user-viewer"))
            )),
            null
        );
        setContext(jwt);
        assertThat(tenantSecurity.canManageUsersInTenantId(TENANT_ID)).isFalse();
    }

    // ----- helpers -----------------------------------------------------------

    private static Jwt jwtFromPlatformRealmWithRoles(List<String> realmRoles) {
        return jwt(
            KC_URL + "/realms/" + PLATFORM_REALM,
            Map.of("realm_access", Map.of("roles", realmRoles)),
            null
        );
    }

    private static Jwt jwt(String issuer, Map<String, Object> extraClaims, Object unused) {
        try {
            var builder = Jwt.withTokenValue("token")
                .header("alg", "none")
                .issuer(new URL(issuer).toString())
                .subject("user-id")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300));
            extraClaims.forEach(builder::claim);
            return builder.build();
        } catch (java.net.MalformedURLException e) {
            throw new AssertionError("bad issuer in test setup: " + issuer, e);
        }
    }

    private static void setContext(Jwt jwt) {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));
    }
}
