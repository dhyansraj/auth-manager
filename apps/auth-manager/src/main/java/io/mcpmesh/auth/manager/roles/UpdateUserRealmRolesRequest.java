package io.mcpmesh.auth.manager.roles;

import jakarta.validation.constraints.NotNull;

import java.util.List;

/**
 * Atomic-replace request body for a user's composite-role assignments.
 * An empty list clears all manageable roles; system / KC-built-in roles
 * are NEVER affected (filtered in the service).
 */
public record UpdateUserRealmRolesRequest(
    @NotNull List<String> roleNames
) {}
