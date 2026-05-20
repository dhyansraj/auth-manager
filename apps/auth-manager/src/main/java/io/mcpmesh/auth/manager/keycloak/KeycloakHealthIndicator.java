package io.mcpmesh.auth.manager.keycloak;

import org.keycloak.representations.info.ServerInfoRepresentation;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * Exposes Keycloak reachability as the {@code keycloak} component of
 * {@code /actuator/health}. UP if the admin client can fetch server
 * info; DOWN with exception detail otherwise.
 *
 * <p>The indicator does a round-trip on every health probe. If
 * Kubernetes probes start hammering this we can add a short cache,
 * but for now correctness over throughput.
 */
@Component("keycloak")
public class KeycloakHealthIndicator implements HealthIndicator {

    private final KeycloakAdminService admin;

    public KeycloakHealthIndicator(KeycloakAdminService admin) {
        this.admin = admin;
    }

    @Override
    public Health health() {
        try {
            ServerInfoRepresentation info = admin.serverInfo();
            String version = info.getSystemInfo() != null
                ? info.getSystemInfo().getVersion()
                : "unknown";
            return Health.up()
                .withDetail("version", version)
                .withDetail("realms-visible", admin.listRealms().size())
                .build();
        } catch (Exception e) {
            return Health.down(e).build();
        }
    }
}
