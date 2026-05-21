package io.mcpmesh.auth.manager.routing.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * A single path-prefix routing rule consumed by OpenResty's route.lua.
 *
 * <p>{@code path} uses glob-style patterns ({@code /api/*}, {@code /*}, etc.).
 * {@code target} is a logical key into {@link RoutingConfig#targets()}
 * (e.g. {@code "backend"}, {@code "frontend"}).
 */
public record RoutingRule(
    @NotBlank String path,
    @NotNull AuthMode authMode,
    @NotBlank String target
) {
}
