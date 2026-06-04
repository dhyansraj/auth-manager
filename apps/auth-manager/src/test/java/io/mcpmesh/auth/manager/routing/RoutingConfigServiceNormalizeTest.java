package io.mcpmesh.auth.manager.routing;

import io.mcpmesh.auth.manager.routing.model.AuthMode;
import io.mcpmesh.auth.manager.routing.model.RoutingConfig;
import io.mcpmesh.auth.manager.routing.model.RoutingRule;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pure unit tests for target normalization (backlog #119: route-target scheme
 * footgun). Targets must be stored as scheme-less {@code host[:port]} so the
 * edge can prepend {@code http://} without producing {@code http://http://...}.
 *
 * <p>Exercised both directly on the helper and through {@code sortBySpecificity}
 * — the same canonicalization the public {@code replaceForTenant} save/publish
 * path applies before persisting to Postgres and publishing to Redis.
 */
class RoutingConfigServiceNormalizeTest {

    @Test
    void strips_http_scheme() {
        assertThat(RoutingConfigService.normalizeTarget("http://192.168.10.50:3000"))
            .isEqualTo("192.168.10.50:3000");
    }

    @Test
    void strips_https_scheme_and_trailing_slash() {
        assertThat(RoutingConfigService.normalizeTarget("https://foo.bar:80/"))
            .isEqualTo("foo.bar:80");
    }

    @Test
    void leaves_plain_host_port_unchanged() {
        assertThat(RoutingConfigService.normalizeTarget("192.168.10.50:8080"))
            .isEqualTo("192.168.10.50:8080");
    }

    @Test
    void leaves_in_cluster_service_name_unchanged() {
        assertThat(RoutingConfigService.normalizeTarget(
            "app1-ui.tenant-app1.svc.cluster.local:80"))
            .isEqualTo("app1-ui.tenant-app1.svc.cluster.local:80");
    }

    @Test
    void scheme_match_is_case_insensitive_and_trims_whitespace() {
        assertThat(RoutingConfigService.normalizeTarget("  HTTP://Host:8080/  "))
            .isEqualTo("Host:8080");
    }

    @Test
    void null_and_blank_pass_through() {
        assertThat(RoutingConfigService.normalizeTarget(null)).isNull();
        assertThat(RoutingConfigService.normalizeTarget("   ")).isEmpty();
    }

    @Test
    void preserves_path_after_host() {
        assertThat(RoutingConfigService.normalizeTarget("https://host:8080/base"))
            .isEqualTo("host:8080/base");
    }

    @Test
    void save_canonicalization_normalizes_all_target_values() {
        RoutingConfig in = new RoutingConfig(
            List.of(
                new RoutingRule("/api/*", AuthMode.REQUIRED, "backend"),
                new RoutingRule("/*",     AuthMode.OPTIONAL, "frontend")
            ),
            Map.of(
                "backend",  "http://192.168.10.50:3000",
                "frontend", "app1-ui.tenant-app1.svc.cluster.local:80"
            )
        );

        RoutingConfig out = RoutingConfigService.sortBySpecificity(in);

        assertThat(out.targets())
            .containsEntry("backend", "192.168.10.50:3000")
            .containsEntry("frontend", "app1-ui.tenant-app1.svc.cluster.local:80");
    }
}
