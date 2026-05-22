package io.mcpmesh.auth.manager.idp;

import jakarta.validation.constraints.NotNull;

/** Body for {@code PUT /tenants/{slug}/identity-providers/{providerId}}. */
public record UpdateProviderRequest(
    @NotNull Boolean enabled
) {}
