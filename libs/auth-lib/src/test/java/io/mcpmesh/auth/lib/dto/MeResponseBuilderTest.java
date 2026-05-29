package io.mcpmesh.auth.lib.dto;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link MeResponseBuilder}, covering the role extraction +
 * normalization shape that every tenant Java backend's {@code /api/me}
 * endpoint depends on.
 */
class MeResponseBuilderTest {

    private static final MeResponse.Tenant TENANT =
        new MeResponse.Tenant("happyfeet", "happyfeet", "Happy Feet", "happyfeet-realm");

    private static final String BACKEND = "happyfeet-backend";

    private static Jwt.Builder baseJwt() {
        return Jwt.withTokenValue("token")
            .header("alg", "none")
            .subject("alice-sub")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(300))
            .claim("email", "alice@example.com")
            .claim("preferred_username", "alice")
            .claim("name", "Alice Example");
    }

    @Test
    void basic_case_two_roles_uppercased() {
        Jwt jwt = baseJwt()
            .claim("resource_access", Map.of(
                BACKEND, Map.of("roles", List.of("ORDER_VIEW", "ORDER_APPROVE"))))
            .build();

        MeResponse out = MeResponseBuilder.fromJwt(jwt, BACKEND, TENANT);

        assertThat(out.user().id()).isEqualTo("alice-sub");
        assertThat(out.user().email()).isEqualTo("alice@example.com");
        assertThat(out.user().preferredUsername()).isEqualTo("alice");
        assertThat(out.user().name()).isEqualTo("Alice Example");
        assertThat(out.context()).isEqualTo("tenant");
        assertThat(out.tenant()).isEqualTo(TENANT);
        assertThat(out.isPlatformAdmin()).isFalse();
        assertThat(out.isTenantAdmin()).isFalse();
        assertThat(out.permissions()).containsExactlyInAnyOrder("ORDER_VIEW", "ORDER_APPROVE");
    }

    @Test
    void no_resource_access_claim_yields_empty_permissions() {
        Jwt jwt = baseJwt().build();

        MeResponse out = MeResponseBuilder.fromJwt(jwt, BACKEND, TENANT);

        assertThat(out.permissions()).isEmpty();
        assertThat(out.isTenantAdmin()).isFalse();
        assertThat(out.user().id()).isEqualTo("alice-sub");
    }

    @Test
    void resource_access_present_but_missing_backend_client_yields_empty_permissions() {
        Jwt jwt = baseJwt()
            .claim("resource_access", Map.of(
                "some-other-client", Map.of("roles", List.of("ROLE_X"))))
            .build();

        MeResponse out = MeResponseBuilder.fromJwt(jwt, BACKEND, TENANT);

        assertThat(out.permissions()).isEmpty();
    }

    @Test
    void backend_client_present_but_roles_missing_or_empty_yields_empty_permissions() {
        Jwt missingRoles = baseJwt()
            .claim("resource_access", Map.of(BACKEND, Map.of()))
            .build();
        assertThat(MeResponseBuilder.fromJwt(missingRoles, BACKEND, TENANT).permissions())
            .isEmpty();

        Jwt emptyRoles = baseJwt()
            .claim("resource_access", Map.of(BACKEND, Map.of("roles", List.of())))
            .build();
        assertThat(MeResponseBuilder.fromJwt(emptyRoles, BACKEND, TENANT).permissions())
            .isEmpty();
    }

    @Test
    void tenant_admin_role_match_flips_the_flag() {
        Jwt jwt = baseJwt()
            .claim("resource_access", Map.of(
                BACKEND, Map.of("roles", List.of("ORDER_VIEW", "OWNER"))))
            .build();

        MeResponse out = MeResponseBuilder.fromJwt(jwt, BACKEND, TENANT, "OWNER", null);

        assertThat(out.isTenantAdmin()).isTrue();
        assertThat(out.permissions()).contains("OWNER", "ORDER_VIEW");

        // Without the admin role on the user, the flag stays false.
        Jwt jwtNoOwner = baseJwt()
            .claim("resource_access", Map.of(
                BACKEND, Map.of("roles", List.of("ORDER_VIEW"))))
            .build();
        assertThat(MeResponseBuilder.fromJwt(jwtNoOwner, BACKEND, TENANT, "OWNER", null)
            .isTenantAdmin()).isFalse();
    }

    @Test
    void extra_permissions_are_unioned_and_uppercased() {
        Jwt jwt = baseJwt()
            .claim("resource_access", Map.of(
                BACKEND, Map.of("roles", List.of("ORDER_VIEW"))))
            .build();

        MeResponse out = MeResponseBuilder.fromJwt(
            jwt, BACKEND, TENANT, null, List.of("static_capability", "ORDER_VIEW"));

        // De-duped; both casing variants collapse to one entry.
        assertThat(out.permissions())
            .containsExactlyInAnyOrder("ORDER_VIEW", "STATIC_CAPABILITY");
    }

    @Test
    void lowercase_roles_get_uppercased() {
        Jwt jwt = baseJwt()
            .claim("resource_access", Map.of(
                BACKEND, Map.of("roles", List.of("order_view", "Order_Approve"))))
            .build();

        MeResponse out = MeResponseBuilder.fromJwt(jwt, BACKEND, TENANT);

        assertThat(out.permissions()).containsExactlyInAnyOrder("ORDER_VIEW", "ORDER_APPROVE");
    }

    @Test
    void null_jwt_throws_npe() {
        assertThatThrownBy(() -> MeResponseBuilder.fromJwt(null, BACKEND, TENANT))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("jwt");
    }

    @Test
    void context_is_always_tenant_and_platform_admin_is_false() {
        Jwt jwt = baseJwt()
            .claim("resource_access", Map.of(
                BACKEND, Map.of("roles", List.of("OWNER"))))
            .build();

        MeResponse out = MeResponseBuilder.fromJwt(jwt, BACKEND, TENANT, "OWNER", null);

        assertThat(out.context()).isEqualTo("tenant");
        assertThat(out.isPlatformAdmin()).isFalse();
    }

    @Test
    void tenant_admin_role_match_is_case_insensitive() {
        // tenantAdminRole "owner" should still flip the flag even though
        // permissions store uppercased values.
        Jwt jwt = baseJwt()
            .claim("resource_access", Map.of(
                BACKEND, Map.of("roles", List.of("owner"))))
            .build();

        MeResponse out = MeResponseBuilder.fromJwt(jwt, BACKEND, TENANT, "owner", null);

        assertThat(out.isTenantAdmin()).isTrue();
        assertThat(out.permissions()).containsExactly("OWNER");
    }

    @Test
    void extra_permissions_alone_with_no_resource_access_still_populate() {
        Jwt jwt = baseJwt().build();

        MeResponse out = MeResponseBuilder.fromJwt(
            jwt, BACKEND, TENANT, null, Set.of("CAP_A", "CAP_B"));

        assertThat(out.permissions()).containsExactlyInAnyOrder("CAP_A", "CAP_B");
    }
}
