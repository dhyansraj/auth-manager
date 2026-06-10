package io.mcpmesh.auth.manager.api.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.Set;

public record CreateUserRequest(
    @NotBlank @Email @Size(max = 255) String email,
    String firstName,
    String lastName,
    /** Roles to assign on the usermanagement client. Defaults to ["user-viewer"] if null/empty. */
    List<String> roles,
    /** If true, send a Set-Password invite email after creation. Default true. */
    Boolean sendInvite,
    /**
     * Optional display name of the inviting user, rendered in the branded
     * invitation email ("X invited you to ..."). Null/blank omits the inviter.
     */
    @Size(max = 255) String inviterName
) {
    public static final Set<String> ALLOWED_ROLES = Set.of("tenant-admin", "tenant-user-manager", "user-viewer");
}
