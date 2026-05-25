package io.mcpmesh.auth.manager.security;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.KeycloakProperties;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
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
 * Unit tests for {@link Permissions}: covers the atomic-permission claim
 * lookup, the per-tenant slug/id realm-match guard, and the platform-admin
 * bypass.
 */
class PermissionsTest {

    private static final String KC_URL = "http://localhost:8180";
    private static final String PLATFORM_REALM = "dev";
    private static final String PLATFORM_ROLE = "platform-admin";

    private static final String APP1_SLUG = "app1";
    private static final String APP1_REALM = "t-app1";
    private static final UUID APP1_ID = UUID.randomUUID();

    private static final String APP2_SLUG = "app2";
    private static final String APP2_REALM = "t-app2";
    private static final UUID APP2_ID = UUID.randomUUID();

    private TenantRepository tenantRepository;
    private KeycloakProperties props;
    private Permissions perms;

    @BeforeEach
    void setUp() {
        tenantRepository = mock(TenantRepository.class);
        props = new KeycloakProperties(
            KC_URL, "master",
            new KeycloakProperties.Admin("admin-cli", "admin", "admin"),
            new KeycloakProperties.Platform(PLATFORM_REALM, PLATFORM_ROLE, null),
            null, null
        );
        perms = new Permissions(tenantRepository, props);

        Tenant app1 = mock(Tenant.class);
        when(app1.getId()).thenReturn(APP1_ID);
        when(app1.getRealmName()).thenReturn(APP1_REALM);
        when(app1.getSlug()).thenReturn(APP1_SLUG);
        when(app1.getDeletedAt()).thenReturn(null);
        when(tenantRepository.findBySlugAndDeletedAtIsNull(APP1_SLUG))
            .thenReturn(Optional.of(app1));
        when(tenantRepository.findById(APP1_ID)).thenReturn(Optional.of(app1));
        when(tenantRepository.findByRealmNameAndDeletedAtIsNull(APP1_REALM))
            .thenReturn(Optional.of(app1));

        Tenant app2 = mock(Tenant.class);
        when(app2.getId()).thenReturn(APP2_ID);
        when(app2.getRealmName()).thenReturn(APP2_REALM);
        when(app2.getSlug()).thenReturn(APP2_SLUG);
        when(app2.getDeletedAt()).thenReturn(null);
        when(tenantRepository.findBySlugAndDeletedAtIsNull(APP2_SLUG))
            .thenReturn(Optional.of(app2));
        when(tenantRepository.findById(APP2_ID)).thenReturn(Optional.of(app2));
        when(tenantRepository.findByRealmNameAndDeletedAtIsNull(APP2_REALM))
            .thenReturn(Optional.of(app2));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // ----- has(perm) ---------------------------------------------------------

    @Test
    void has_returnsFalse_whenNoJwtInContext() {
        // Anonymous (no JWT auth) -> false.
        SecurityContextHolder.getContext().setAuthentication(
            new AnonymousAuthenticationToken("k", "anon",
                List.of(new SimpleGrantedAuthority("ROLE_ANON"))));
        assertThat(perms.has("TENANT_CREATE")).isFalse();
    }

    @Test
    void has_returnsFalse_whenAuthenticationIsNull() {
        // No authentication at all -> false.
        assertThat(perms.has("TENANT_CREATE")).isFalse();
    }

    @Test
    void has_returnsTrue_whenPermPresentInUsermanagementClaim() {
        setContext(jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("TENANT_VIEW", "ROUTES_EDIT"))
            ))
        ));
        assertThat(perms.has("TENANT_VIEW")).isTrue();
        assertThat(perms.has("ROUTES_EDIT")).isTrue();
    }

    @Test
    void has_returnsFalse_whenPermAbsentFromClaim() {
        setContext(jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("TENANT_VIEW"))
            ))
        ));
        assertThat(perms.has("ROUTES_EDIT")).isFalse();
    }

    @Test
    void has_returnsFalse_whenResourceAccessMissing() {
        setContext(jwt(KC_URL + "/realms/" + APP1_REALM, Map.of()));
        assertThat(perms.has("TENANT_VIEW")).isFalse();
    }

    @Test
    void has_returnsFalse_whenUsermanagementClientMissing() {
        setContext(jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of("resource_access", Map.of(
                "some-other-client", Map.of("roles", List.of("TENANT_VIEW"))
            ))
        ));
        assertThat(perms.has("TENANT_VIEW")).isFalse();
    }

    // ----- hasOnTenant(slug, perm) ------------------------------------------

    @Test
    void hasOnTenant_returnsFalse_whenNoJwt() {
        assertThat(perms.hasOnTenant(APP1_SLUG, "TENANT_VIEW")).isFalse();
    }

    @Test
    void hasOnTenant_returnsTrue_whenJwtRealmMatchesTenantRealmAndPermPresent() {
        setContext(jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("ROUTES_EDIT"))
            ))
        ));
        assertThat(perms.hasOnTenant(APP1_SLUG, "ROUTES_EDIT")).isTrue();
    }

    @Test
    void hasOnTenant_returnsFalse_whenJwtRealmDoesNotMatchTenantRealm() {
        // Caller from app1 trying to act on app2 — same perm, different realm.
        setContext(jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("ROUTES_EDIT"))
            ))
        ));
        assertThat(perms.hasOnTenant(APP2_SLUG, "ROUTES_EDIT")).isFalse();
    }

    @Test
    void hasOnTenant_returnsFalse_whenPermAbsentEvenWhenRealmMatches() {
        setContext(jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("TENANT_VIEW"))
            ))
        ));
        assertThat(perms.hasOnTenant(APP1_SLUG, "ROUTES_EDIT")).isFalse();
    }

    @Test
    void hasOnTenant_returnsTrue_forPlatformAdmin_onAnyTenant() {
        // Platform-admin bypass: no resource_access claim needed.
        setContext(jwtFromPlatformRealmWithRoles(List.of(PLATFORM_ROLE)));
        assertThat(perms.hasOnTenant(APP1_SLUG, "ROUTES_EDIT")).isTrue();
        assertThat(perms.hasOnTenant(APP2_SLUG, "TENANT_DELETE")).isTrue();
    }

    @Test
    void hasOnTenant_returnsFalse_forMissingTenant() {
        // Caller has the perm and a valid JWT but the slug doesn't exist.
        setContext(jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("ROUTES_EDIT"))
            ))
        ));
        when(tenantRepository.findBySlugAndDeletedAtIsNull("ghost"))
            .thenReturn(Optional.empty());
        assertThat(perms.hasOnTenant("ghost", "ROUTES_EDIT")).isFalse();
    }

    // ----- hasOnTenantId(uuid, perm) ----------------------------------------

    @Test
    void hasOnTenantId_returnsTrue_whenRealmMatchesAndPermPresent() {
        setContext(jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("USER_INVITE"))
            ))
        ));
        assertThat(perms.hasOnTenantId(APP1_ID, "USER_INVITE")).isTrue();
    }

    @Test
    void hasOnTenantId_returnsFalse_whenRealmDoesNotMatch() {
        setContext(jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("USER_INVITE"))
            ))
        ));
        assertThat(perms.hasOnTenantId(APP2_ID, "USER_INVITE")).isFalse();
    }

    @Test
    void hasOnTenantId_returnsTrue_forPlatformAdmin() {
        setContext(jwtFromPlatformRealmWithRoles(List.of(PLATFORM_ROLE)));
        assertThat(perms.hasOnTenantId(APP1_ID, "USER_DISABLE")).isTrue();
    }

    @Test
    void hasOnTenantId_returnsFalse_forMissingTenant() {
        setContext(jwt(
            KC_URL + "/realms/" + APP1_REALM,
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("USER_INVITE"))
            ))
        ));
        UUID ghost = UUID.randomUUID();
        when(tenantRepository.findById(ghost)).thenReturn(Optional.empty());
        assertThat(perms.hasOnTenantId(ghost, "USER_INVITE")).isFalse();
    }

    @Test
    void hasOnTenantId_returnsFalse_forSoftDeletedTenant() {
        // Tenant exists but has been soft-deleted; treat as missing.
        Tenant deleted = mock(Tenant.class);
        UUID id = UUID.randomUUID();
        when(deleted.getId()).thenReturn(id);
        when(deleted.getRealmName()).thenReturn("t-deleted");
        when(deleted.getDeletedAt()).thenReturn(Instant.now());
        when(tenantRepository.findById(id)).thenReturn(Optional.of(deleted));

        setContext(jwt(
            KC_URL + "/realms/t-deleted",
            Map.of("resource_access", Map.of(
                "usermanagement", Map.of("roles", List.of("USER_INVITE"))
            ))
        ));
        assertThat(perms.hasOnTenantId(id, "USER_INVITE")).isFalse();
    }

    // ----- helpers ----------------------------------------------------------

    private static Jwt jwtFromPlatformRealmWithRoles(List<String> realmRoles) {
        return jwt(
            KC_URL + "/realms/" + PLATFORM_REALM,
            Map.of("realm_access", Map.of("roles", realmRoles))
        );
    }

    private static Jwt jwt(String issuer, Map<String, Object> extraClaims) {
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
