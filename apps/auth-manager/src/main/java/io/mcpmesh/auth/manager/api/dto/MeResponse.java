package io.mcpmesh.auth.manager.api.dto;

import java.util.Set;

/**
 * Shape returned by {@code GET /api/v1/me} on the auth-manager control plane.
 *
 * <p>This record is intentionally identical in shape to
 * {@code io.mcpmesh.auth.lib.dto.MeResponse} (used by tenant-app backends)
 * so the same client-side helper can decode both. We duplicate the type
 * rather than depending on auth-lib because auth-manager runs as a
 * multi-realm control plane and shouldn't drag in auth-lib's single-realm
 * autoconfig.
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
