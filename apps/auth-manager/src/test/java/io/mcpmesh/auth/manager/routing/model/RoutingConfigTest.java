package io.mcpmesh.auth.manager.routing.model;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RoutingConfigTest {

    @Test
    void rejects_empty_rules() {
        assertThatThrownBy(() -> new RoutingConfig(List.of(), Map.of()))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("non-empty");
    }

    @Test
    void rejects_null_rules() {
        assertThatThrownBy(() -> new RoutingConfig(null, Map.of()))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("non-empty");
    }

    @Test
    void rejects_rule_set_without_catch_all() {
        assertThatThrownBy(() -> new RoutingConfig(
            List.of(new RoutingRule("/api/*", AuthMode.REQUIRED, "backend")),
            Map.of("backend", "svc:8080")
        ))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("/*");
    }

    @Test
    void accepts_minimal_catch_all_only() {
        RoutingConfig cfg = new RoutingConfig(
            List.of(new RoutingRule("/*", AuthMode.OPTIONAL, "frontend")),
            Map.of("frontend", "svc:80")
        );
        assertThat(cfg.rules()).hasSize(1);
        assertThat(cfg.targets()).containsEntry("frontend", "svc:80");
    }

    @Test
    void accepts_typical_two_rule_set() {
        RoutingConfig cfg = new RoutingConfig(
            List.of(
                new RoutingRule("/api/*", AuthMode.REQUIRED, "backend"),
                new RoutingRule("/*",     AuthMode.OPTIONAL, "frontend")
            ),
            Map.of(
                "backend",  "be:8080",
                "frontend", "fe:80"
            )
        );
        assertThat(cfg.rules()).hasSize(2);
    }

    @Test
    void null_targets_defaults_to_empty_map() {
        RoutingConfig cfg = new RoutingConfig(
            List.of(new RoutingRule("/*", AuthMode.PUBLIC, "noop")),
            null
        );
        assertThat(cfg.targets()).isEmpty();
    }

    @Test
    void targets_and_rules_are_immutable() {
        java.util.List<RoutingRule> rules = new java.util.ArrayList<>();
        rules.add(new RoutingRule("/*", AuthMode.PUBLIC, "x"));
        java.util.Map<String, String> targets = new java.util.HashMap<>();
        targets.put("x", "v");

        RoutingConfig cfg = new RoutingConfig(rules, targets);

        // Mutating the inputs after construction does not affect the record.
        rules.add(new RoutingRule("/extra", AuthMode.PUBLIC, "y"));
        targets.put("y", "v2");

        assertThat(cfg.rules()).hasSize(1);
        assertThat(cfg.targets()).hasSize(1);
    }
}
