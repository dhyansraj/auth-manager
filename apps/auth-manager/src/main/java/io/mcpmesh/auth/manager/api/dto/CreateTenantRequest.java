package io.mcpmesh.auth.manager.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.Map;

/**
 * Request body for {@code POST /api/v1/tenants}.
 *
 * @param slug         DNS-safe identifier; will become part of the public hostname.
 * @param displayName  Human-readable name shown in the UI.
 * @param settings     Free-form per-tenant config blob (stored as JSONB).
 */
public record CreateTenantRequest(

    @NotBlank
    @Size(min = 3, max = 63)
    @Pattern(regexp = "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$",
             message = "must be lowercase alphanumeric, hyphens allowed, no leading/trailing hyphen")
    String slug,

    @NotBlank
    @Size(min = 1, max = 100)
    String displayName,

    Map<String, Object> settings
) {}
