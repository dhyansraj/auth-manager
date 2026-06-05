package io.mcpmesh.auth.manager.keycloak;

import io.mcpmesh.auth.manager.routing.RoutingConfigService;
import io.mcpmesh.auth.manager.routing.RoutingTableService;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for the "first broker login auto-link" flow wiring
 * (backlog #94). Runs against a real Keycloak container.
 */
@SpringBootTest(properties = {
    "spring.autoconfigure.exclude=" +
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration," +
        "org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration"
})
@Testcontainers
class AutoLinkFlowIT {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16");

    @Container
    static GenericContainer<?> keycloak = new GenericContainer<>("quay.io/keycloak/keycloak:26.6.1")
        .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
        .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
        .withEnv("KC_HEALTH_ENABLED", "true")
        .withCommand("start-dev", "--http-port=8080")
        .withExposedPorts(8080, 9000)
        .waitingFor(Wait.forHttp("/health/ready").forPort(9000).withStartupTimeout(Duration.ofMinutes(2)));

    @DynamicPropertySource
    static void keycloakProps(DynamicPropertyRegistry registry) {
        String url = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
        registry.add("keycloak.url", () -> url);
        registry.add("keycloak.realm", () -> "master");
        registry.add("keycloak.admin.client-id", () -> "admin-cli");
        registry.add("keycloak.admin.username", () -> "admin");
        registry.add("keycloak.admin.password", () -> "admin");
    }

    @Autowired KeycloakAdminService keycloakAdmin;
    @Autowired IdentityProvidersBootstrap idpBootstrap;
    @Autowired Keycloak admin;

    @MockitoBean RoutingTableService routingTable;
    @MockitoBean RoutingConfigService routingConfigService;

    private String realm;

    @BeforeEach
    void setUp() {
        realm = "t-autolink-" + UUID.randomUUID().toString().substring(0, 8);
        keycloakAdmin.createRealm(realm, "Auto Link IT");
        keycloakAdmin.invalidateAdminToken();
    }

    @Test
    void ensureAutoLinkFlow_createsFlow_withAutoLinkRequiredAndConfirmDisabled() {
        String alias = keycloakAdmin.ensureAutoLinkFlow(realm);
        assertThat(alias).isEqualTo(KeycloakAdminService.FIRST_BROKER_LOGIN_AUTOLINK);

        AuthenticationManagementResource flows = admin.realm(realm).flows();

        boolean flowExists = flows.getFlows().stream()
            .map(AuthenticationFlowRepresentation::getAlias)
            .anyMatch(KeycloakAdminService.FIRST_BROKER_LOGIN_AUTOLINK::equals);
        assertThat(flowExists).isTrue();

        List<AuthenticationExecutionInfoRepresentation> execs =
            flows.getExecutions(KeycloakAdminService.FIRST_BROKER_LOGIN_AUTOLINK);

        AuthenticationExecutionInfoRepresentation autoLink = execs.stream()
            .filter(e -> "idp-auto-link".equals(e.getProviderId()))
            .findFirst().orElseThrow(() -> new AssertionError("idp-auto-link execution missing"));
        assertThat(autoLink.getRequirement()).isEqualTo("REQUIRED");

        AuthenticationExecutionInfoRepresentation confirmLink = execs.stream()
            .filter(e -> "idp-confirm-link".equals(e.getProviderId()))
            .findFirst().orElseThrow(() -> new AssertionError("idp-confirm-link execution missing"));
        assertThat(confirmLink.getRequirement()).isEqualTo("DISABLED");
    }

    @Test
    void ensureAutoLinkFlow_isIdempotent() {
        keycloakAdmin.ensureAutoLinkFlow(realm);
        // Second call must be a no-op, not throw, not duplicate the flow.
        String alias = keycloakAdmin.ensureAutoLinkFlow(realm);
        assertThat(alias).isEqualTo(KeycloakAdminService.FIRST_BROKER_LOGIN_AUTOLINK);

        long count = admin.realm(realm).flows().getFlows().stream()
            .map(AuthenticationFlowRepresentation::getAlias)
            .filter(KeycloakAdminService.FIRST_BROKER_LOGIN_AUTOLINK::equals)
            .count();
        assertThat(count).isEqualTo(1);
    }

    @Test
    void repointIdpsToAutoLink_repointsIdpAtAutoLinkFlow() {
        // Create an IdP referencing the built-in first-broker-login flow.
        IdentityProviderRepresentation rep = new IdentityProviderRepresentation();
        rep.setAlias("google");
        rep.setProviderId("google");
        rep.setEnabled(true);
        rep.setFirstBrokerLoginFlowAlias(KeycloakAdminService.FIRST_BROKER_LOGIN_FLOW);
        rep.setConfig(Map.of("clientId", "x", "clientSecret", "y"));
        try (Response r = admin.realm(realm).identityProviders().create(rep)) {
            assertThat(r.getStatus()).isBetween(200, 299);
        }

        idpBootstrap.repointIdpsToAutoLink(realm);

        IdentityProviderRepresentation after =
            admin.realm(realm).identityProviders().get("google").toRepresentation();
        assertThat(after.getFirstBrokerLoginFlowAlias())
            .isEqualTo(KeycloakAdminService.FIRST_BROKER_LOGIN_AUTOLINK);
    }
}
