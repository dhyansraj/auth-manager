package io.mcpmesh.auth.manager.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record CreateAppRequest(

    @NotBlank
    @Size(min = 3, max = 63)
    @Pattern(regexp = "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$",
             message = "must be lowercase alphanumeric, hyphens allowed, no leading/trailing hyphen")
    String slug,

    @NotBlank
    @Size(min = 1, max = 100)
    String displayName
) {}
