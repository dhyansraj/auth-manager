package io.mcpmesh.auth.manager.routing;

import io.mcpmesh.auth.manager.routing.model.AuthMode;
import io.mcpmesh.auth.manager.routing.model.RoutingConfig;
import io.mcpmesh.auth.manager.routing.model.RoutingRule;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pure unit tests for the routing rule specificity comparator. No Spring,
 * no DB, no Redis — exercises the static sort helper directly so the
 * canonicalization behavior is documented and locked in.
 */
class RoutingConfigServiceSortTest {

    @Test
    void catch_all_is_pushed_to_the_end_even_if_added_first() {
        RoutingConfig in = new RoutingConfig(
            List.of(
                new RoutingRule("/*",            AuthMode.OPTIONAL, "frontend"),
                new RoutingRule("/api/*",        AuthMode.REQUIRED, "backend"),
                new RoutingRule("/ops/redis/*",  AuthMode.PUBLIC,   "redis")
            ),
            Map.of("frontend", "fe:80", "backend", "be:8080", "redis", "rc:80")
        );

        RoutingConfig out = RoutingConfigService.sortBySpecificity(in);

        assertThat(out.rules()).extracting(RoutingRule::path).containsExactly(
            "/ops/redis/*",
            "/api/*",
            "/*"
        );
    }

    @Test
    void exact_paths_outrank_wildcards_of_the_same_or_longer_length() {
        RoutingConfig in = new RoutingConfig(
            List.of(
                new RoutingRule("/api/*",  AuthMode.REQUIRED, "backend"),
                new RoutingRule("/health", AuthMode.PUBLIC,   "backend"),
                new RoutingRule("/*",      AuthMode.OPTIONAL, "frontend")
            ),
            Map.of("frontend", "fe:80", "backend", "be:8080")
        );

        RoutingConfig out = RoutingConfigService.sortBySpecificity(in);

        assertThat(out.rules()).extracting(RoutingRule::path).containsExactly(
            "/health",   // exact, beats any wildcard
            "/api/*",
            "/*"
        );
    }

    @Test
    void longer_wildcard_prefix_wins_within_wildcard_bucket() {
        RoutingConfig in = new RoutingConfig(
            List.of(
                new RoutingRule("/api/*",            AuthMode.REQUIRED, "backend"),
                new RoutingRule("/api/v1/users/*",   AuthMode.REQUIRED, "backend"),
                new RoutingRule("/*",                AuthMode.OPTIONAL, "frontend")
            ),
            Map.of("frontend", "fe:80", "backend", "be:8080")
        );

        RoutingConfig out = RoutingConfigService.sortBySpecificity(in);

        assertThat(out.rules()).extracting(RoutingRule::path).containsExactly(
            "/api/v1/users/*",
            "/api/*",
            "/*"
        );
    }

    @Test
    void sort_preserves_rule_fields_and_targets() {
        RoutingRule r1 = new RoutingRule("/*",     AuthMode.OPTIONAL, "frontend", false);
        RoutingRule r2 = new RoutingRule("/api/*", AuthMode.REQUIRED, "backend",  true);

        RoutingConfig out = RoutingConfigService.sortBySpecificity(new RoutingConfig(
            List.of(r1, r2),
            Map.of("frontend", "fe:80", "backend", "be:8080")
        ));

        assertThat(out.rules()).containsExactly(r2, r1);
        assertThat(out.targets()).containsEntry("backend", "be:8080")
                                 .containsEntry("frontend", "fe:80");
    }

    @Test
    void already_sorted_input_is_a_no_op() {
        RoutingConfig in = new RoutingConfig(
            List.of(
                new RoutingRule("/ops/redis/*", AuthMode.PUBLIC,   "redis"),
                new RoutingRule("/api/*",       AuthMode.REQUIRED, "backend"),
                new RoutingRule("/*",           AuthMode.OPTIONAL, "frontend")
            ),
            Map.of("frontend", "fe:80", "backend", "be:8080", "redis", "rc:80")
        );

        RoutingConfig out = RoutingConfigService.sortBySpecificity(in);

        assertThat(out.rules()).extracting(RoutingRule::path).containsExactly(
            "/ops/redis/*", "/api/*", "/*"
        );
    }
}
