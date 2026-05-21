package io.mcpmesh.auth.manager.routing.model;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.List;
import java.util.Map;

/**
 * Per-tenant routing config persisted as JSONB on the tenants table and
 * mirrored to Redis as {@code route:<slug>}. Validated on construction so
 * any path that reaches the DB or Redis carries a well-formed rule set.
 *
 * <p>Invariants enforced here (in addition to per-field bean-validation):
 * <ul>
 *   <li>{@code rules} must be non-empty.</li>
 *   <li>At least one rule must have path {@code /*} (catch-all). Without
 *       this, OpenResty has nowhere to send unmatched requests.</li>
 * </ul>
 */
public record RoutingConfig(
    @NotEmpty @Valid List<RoutingRule> rules,
    @NotNull Map<String, String> targets
) {
    public RoutingConfig {
        if (rules == null || rules.isEmpty()) {
            throw new IllegalArgumentException("rules must be non-empty");
        }
        if (targets == null) {
            targets = Map.of();
        }
        boolean hasCatchAll = rules.stream().anyMatch(r -> r != null && "/*".equals(r.path()));
        if (!hasCatchAll) {
            throw new IllegalArgumentException("rules must contain a /* catch-all");
        }
        // Defensive copies so the record is effectively immutable.
        rules = List.copyOf(rules);
        targets = Map.copyOf(targets);
    }
}
