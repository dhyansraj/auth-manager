package io.mcpmesh.auth.manager.roles;

/**
 * Raised by {@link RolesService#delete(String, String, String)} when the
 * caller tries to drop a composite role still assigned to one or more users.
 * Mapped to HTTP 409 with body {@code {error: "role_in_use", userCount: N}}.
 */
public class RoleInUseException extends RuntimeException {
    private final String roleName;
    private final int userCount;

    public RoleInUseException(String roleName, int userCount) {
        super("Role " + roleName + " is assigned to " + userCount + " user(s)");
        this.roleName = roleName;
        this.userCount = userCount;
    }

    public String roleName() { return roleName; }
    public int userCount() { return userCount; }
}
