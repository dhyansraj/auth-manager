package io.mcpmesh.auth.manager.roles;

import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.constraints.NotBlank;

/**
 * An atomic permission exposed by an app -- modeled as a KC client role on
 * the app's confidential client (e.g. {@code orders:order:approve}). Read-only
 * from auth-manager's perspective: defined by dev via the access manifest.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record PermissionDto(
    @NotBlank String client,
    @NotBlank String name,
    String description
) {
    public PermissionDto(String client, String name) {
        this(client, name, null);
    }
}
