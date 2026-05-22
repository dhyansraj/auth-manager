package io.mcpmesh.auth.manager.roles;

/**
 * Raised when a composite-role lookup or update targets a name that does
 * not exist (or has been hidden as system). Mapped to HTTP 404.
 */
public class RoleNotFoundException extends RuntimeException {
    public RoleNotFoundException(String roleName) {
        super("Role not found: " + roleName);
    }
}
