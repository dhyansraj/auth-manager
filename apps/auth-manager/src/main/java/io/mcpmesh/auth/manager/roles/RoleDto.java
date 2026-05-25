package io.mcpmesh.auth.manager.roles;

import java.util.List;

/**
 * A composite (custom) role: a KC realm role in a tenant realm whose
 * constituents are zero or more atomic permissions (client roles).
 * Admin-created via the UI; KC token expansion includes both the
 * composite name and its constituents in {@code resource_access.<client>.roles}.
 *
 * <p>{@code userCount} is the number of users currently assigned the role
 * (used by the UI + the delete-guard). {@code system=true} marks roles
 * managed by the platform (e.g. {@code tenant-admin}); those are hidden from
 * the composite-role CRUD surface.
 *
 * <p>{@code isDefault=true} marks roles auto-assigned to every new user at
 * signup -- either as a member of the {@code default-roles-<realm>} composite
 * OR via a "Hardcoded Realm Role" IdP mapper on any enabled IdP. The popover
 * uses this to render the checkbox as checked + disabled (the user
 * effectively has the role; KC has no per-user "exclude" semantic).
 */
public record RoleDto(
    String name,
    String description,
    List<PermissionDto> permissions,
    int userCount,
    boolean system,
    boolean isDefault
) {}
