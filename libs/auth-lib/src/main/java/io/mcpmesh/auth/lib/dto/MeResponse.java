package io.mcpmesh.auth.lib.dto;

import java.util.Set;

/**
 * The shared "who am I + what can I do?" payload returned by every
 * tenant-app backend's {@code GET /api/me} and by the auth-manager's
 * {@code GET /api/v1/me}.
 *
 * <p>The UI uses this single object to drive both routing (which app
 * to land on / which navigation entries to show) and visibility
 * (which buttons/actions to enable). Keeping the shape identical on
 * the platform side and the tenant side lets one client-side helper
 * decode both.
 *
 * <p>Field semantics:
 * <ul>
 *   <li>{@code context}: {@code "platform"} when the caller is signed
 *       into the platform realm AND carries the platform-admin role,
 *       otherwise {@code "tenant"}.</li>
 *   <li>{@code tenant}: null in platform context; populated with the
 *       caller's resolved tenant in tenant context.</li>
 *   <li>{@code permissions}: flat, deduped, uppercased strings such as
 *       {@code ORDER_VIEW} (UMA-derived) or {@code TENANT_LIST_ALL}
 *       (platform capability). Includes both UMA permissions and any
 *       static capability strings the backend chooses to expose.</li>
 * </ul>
 */
public record MeResponse(
    User user,
    String context,
    Tenant tenant,
    boolean isPlatformAdmin,
    boolean isTenantAdmin,
    Set<String> permissions
) {
    public record User(String id, String email, String preferredUsername, String name) {}

    public record Tenant(String id, String slug, String displayName, String realmName) {}
}
