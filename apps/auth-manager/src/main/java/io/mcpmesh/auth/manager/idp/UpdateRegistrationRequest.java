package io.mcpmesh.auth.manager.idp;

import jakarta.validation.constraints.NotNull;

/** Body for {@code PUT /tenants/{slug}/identity-providers/registration}. */
public record UpdateRegistrationRequest(
    @NotNull Boolean inviteOnly
) {}
