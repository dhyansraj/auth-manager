package io.mcpmesh.auth.manager.roles;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.List;

public record CreateRoleRequest(
    @NotBlank @Size(min = 1, max = 50) String name,
    String description,
    @NotNull @Valid List<PermissionRef> permissions
) {
    public record PermissionRef(
        @NotBlank String client,
        @NotBlank String name
    ) {}
}
