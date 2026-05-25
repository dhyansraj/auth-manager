package io.mcpmesh.auth.manager.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;

/**
 * PUT body for replacing an app's service-account user assignments on the
 * {@code usermanagement} client. Each permission name must exist as a client
 * role on {@code usermanagement} in the tenant's realm.
 */
public record UpdateServiceAccountPermissionsRequest(
    @NotNull List<@NotBlank String> permissions
) {}
