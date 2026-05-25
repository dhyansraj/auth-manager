package io.mcpmesh.auth.manager.roles;

import jakarta.validation.constraints.NotNull;

import java.util.List;

/**
 * Atomic-replace request body for a user's role assignments.
 *
 * <ul>
 *   <li>{@code roleNames}: composite (custom) realm role names to assign.
 *       An empty list clears all manageable composite roles. KC built-in /
 *       system realm roles are NEVER affected (filtered in the service).</li>
 *   <li>{@code systemRoles}: optional. When {@code null}, the caller's
 *       request leaves the user's system client roles on the
 *       {@code usermanagement} client untouched (backward-compatible with
 *       callers that only manage composite roles). When non-null, the
 *       service atomically reconciles the user's system client roles to
 *       the given set (filtered to the manageable subset:
 *       {@code tenant-admin}, {@code tenant-user-manager}). The
 *       {@code user-viewer} baseline is always preserved regardless of
 *       what the caller sends.</li>
 * </ul>
 *
 * <p>Authorization note: a request with {@code systemRoles != null} is a
 * <em>privileged</em> operation and requires {@code canManageTenant}
 * (tenant-admin or platform-admin), not the lighter
 * {@code canManageUsersInTenant}. The controller enforces this stricter
 * gate when {@code systemRoles} is present, preventing privilege
 * escalation by tenant-user-manager holders.
 */
public record UpdateUserRealmRolesRequest(
    @NotNull List<String> roleNames,
    List<String> systemRoles
) {
    public UpdateUserRealmRolesRequest(List<String> roleNames) {
        this(roleNames, null);
    }
}
