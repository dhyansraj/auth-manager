package io.mcpmesh.auth.lib.dto;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Constructs a {@link MeResponse} from a Spring Security {@link Jwt} and the
 * caller's backend client_id. Pulls the user's app-level permissions out of
 * the JWT's {@code resource_access.<backendClientId>.roles} array, normalizes
 * them to uppercase, and assembles the full payload.
 *
 * <p>Intended use: the {@code /api/me} endpoint of every tenant Java backend.
 *
 * <pre>{@code
 * @GetMapping("/api/me")
 * public MeResponse me(@AuthenticationPrincipal Jwt jwt) {
 *     return MeResponseBuilder.fromJwt(jwt, "happyfeet-backend", TENANT);
 * }
 * }</pre>
 *
 * <p>Mirrors the Python {@code build_me_response} helper in
 * {@code mcp-mesh-auth-lib} (PyPI).
 */
public final class MeResponseBuilder {
    private MeResponseBuilder() {}

    /**
     * @param jwt              the authenticated user's JWT (from Spring Security context)
     * @param backendClientId  KC client_id of THIS backend; roles under this key
     *                         in {@code resource_access} become permissions
     * @param tenant           the {@link MeResponse.Tenant} describing this backend's tenant
     */
    public static MeResponse fromJwt(Jwt jwt, String backendClientId, MeResponse.Tenant tenant) {
        return fromJwt(jwt, backendClientId, tenant, null, null);
    }

    /**
     * @param jwt              the authenticated user's JWT (from Spring Security context).
     *                         Must be non-null; an NPE is thrown otherwise.
     * @param backendClientId  KC client_id of THIS backend; roles under this key
     *                         in {@code resource_access} become permissions
     * @param tenant           the {@link MeResponse.Tenant} describing this backend's tenant
     * @param tenantAdminRole  role string whose presence flips {@code isTenantAdmin=true}
     *                         (null = never)
     * @param extraPermissions extra static capability strings to union in (null = none).
     *                         Uppercased on the way in to match the resource_access shape.
     */
    public static MeResponse fromJwt(
        Jwt jwt,
        String backendClientId,
        MeResponse.Tenant tenant,
        @Nullable String tenantAdminRole,
        @Nullable Collection<String> extraPermissions
    ) {
        Objects.requireNonNull(jwt, "jwt must not be null");

        MeResponse.User user = new MeResponse.User(
            jwt.getSubject(),
            jwt.getClaimAsString("email"),
            jwt.getClaimAsString("preferred_username"),
            jwt.getClaimAsString("name"));

        Set<String> permissions = new LinkedHashSet<>();
        for (String role : extractClientRoles(jwt, backendClientId)) {
            permissions.add(role.toUpperCase(Locale.ROOT));
        }
        if (extraPermissions != null) {
            for (String p : extraPermissions) {
                if (p != null) permissions.add(p.toUpperCase(Locale.ROOT));
            }
        }

        boolean isTenantAdmin = tenantAdminRole != null
            && permissions.contains(tenantAdminRole.toUpperCase(Locale.ROOT));

        return new MeResponse(
            user,
            "tenant",
            tenant,
            false,
            isTenantAdmin,
            permissions);
    }

    private static Collection<String> extractClientRoles(Jwt jwt, String backendClientId) {
        Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
        if (resourceAccess == null) return Set.of();
        Object client = resourceAccess.get(backendClientId);
        if (!(client instanceof Map<?, ?> clientMap)) return Set.of();
        Object roles = clientMap.get("roles");
        if (!(roles instanceof Collection<?> rolesCol)) return Set.of();
        Set<String> out = new LinkedHashSet<>();
        for (Object r : rolesCol) {
            if (r == null) continue;
            out.add(r.toString());
        }
        return out;
    }
}
