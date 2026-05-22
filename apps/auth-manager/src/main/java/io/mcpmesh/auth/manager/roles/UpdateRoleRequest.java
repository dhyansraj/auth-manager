package io.mcpmesh.auth.manager.roles;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public record UpdateRoleRequest(
    String description,
    @NotNull @Valid List<CreateRoleRequest.PermissionRef> permissions
) {}
