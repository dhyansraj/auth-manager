package io.mcpmesh.auth.manager.security;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.KeycloakProperties;
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

    private TenantService tenants;
    private KeycloakProperties props;
    private TenantSecurity tenantSecurity;

    @BeforeEach
    void setUp() {
        tenants = mock(TenantService.class);
        props = new KeycloakProperties(
            KC_URL, "master",
            new KeycloakProperties.Admin("admin-cli", "admin", "admin"),
            new KeycloakProperties.Platform(PLATFORM_REALM, PLATFORM_ROLE),
            null, null
        );
        tenantSecurity = new TenantSecurity(tenants, props);

        Tenant tenant = mock(Tenant.class);
        when(tenant.getRealmName()).thenReturn(TENANT_REALM);
        when(tenants.get(TENANT_ID)).thenReturn(tenant);
        when(tenants.getBySlug(TENANT_SLUG)).thenReturn(tenant);
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
