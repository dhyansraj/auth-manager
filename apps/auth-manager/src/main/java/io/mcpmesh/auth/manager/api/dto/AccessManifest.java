package io.mcpmesh.auth.manager.api.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AccessManifest(
    @NotNull List<@NotBlank String> roles,
    @NotNull @Valid List<ResourceSpec> resources,
    @NotNull Map<String, @Valid List<RolePermission>> rolePermissions
) {
    public record ResourceSpec(
        @NotBlank String name,
        @NotNull List<@NotBlank String> scopes
    ) {}

    public record RolePermission(
        @NotBlank String resource,
        @NotNull List<@NotBlank String> scopes
    ) {}
}
