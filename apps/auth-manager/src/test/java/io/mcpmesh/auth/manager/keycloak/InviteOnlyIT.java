package io.mcpmesh.auth.manager.keycloak;

import io.mcpmesh.auth.manager.routing.RoutingConfigService;
import io.mcpmesh.auth.manager.routing.RoutingTableService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for the per-tenant invite-only toggle
 * ({@link KeycloakAdminService#setInviteOnly}). Asserts the empirically-derived
 * recipe: in invite-only mode an {@code idp-detect-existing-broker-user}
 * execution is added REQUIRED at the TOP of the "User creation or linking"
 * subflow (before "Handle Existing Account"), {@code idp-create-user-if-unique}
 * is DISABLED, the "Handle Existing Account" subflow is REQUIRED, and the
 * realm's {@code registrationAllowed} flag is false. The open posture restores
 * detect=DISABLED, create-if-unique=ALTERNATIVE, Handle Existing
 * Account=ALTERNATIVE, registrationAllowed=true. Re-applying is stable
 * (idempotent) and does not add a second detect execution.
 *
 * <p>Runs against a real Keycloak container. Like {@link AutoLinkFlowIT}, this
 * cannot run in CI here (testcontainers/docker-java vs Docker 29
 * incompatibility); KC behavior is validated separately against a live
 * instance.
 */
@SpringBootTest(properties = {
    "spring.autoconfigure.exclude=" +
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration," +
        "org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration"
})
@Testcontainers
class InviteOnlyIT {

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
    @Autowired Keycloak admin;

    @MockitoBean RoutingTableService routingTable;
    @MockitoBean RoutingConfigService routingConfigService;

    private String realm;

    @BeforeEach
    void setUp() {
        realm = "t-inviteonly-" + UUID.randomUUID().toString().substring(0, 8);
        keycloakAdmin.createRealm(realm, "Invite Only IT");
        keycloakAdmin.invalidateAdminToken();
        keycloakAdmin.ensureAutoLinkFlow(realm);
    }

    private List<AuthenticationExecutionInfoRepresentation> executions() {
        AuthenticationManagementResource flows = admin.realm(realm).flows();
        return flows.getExecutions(KeycloakAdminService.FIRST_BROKER_LOGIN_AUTOLINK);
    }

    private String requirementByProvider(String providerId) {
        return executions().stream()
            .filter(e -> providerId.equals(e.getProviderId()))
            .map(AuthenticationExecutionInfoRepresentation::getRequirement)
            .findFirst()
            .orElseThrow(() -> new AssertionError(providerId + " execution missing"));
    }

    private String handleExistingAccountRequirement() {
        return executions().stream()
            .filter(e -> Boolean.TRUE.equals(e.getAuthenticationFlow()))
            .filter(e -> e.getDisplayName() != null
                && e.getDisplayName().endsWith("Handle Existing Account"))
            .map(AuthenticationExecutionInfoRepresentation::getRequirement)
            .findFirst()
            .orElseThrow(() -> new AssertionError("Handle Existing Account subflow missing"));
    }

    /** Flat-list position of the detect leaf (by providerId), or -1 if absent. */
    private int detectPosition() {
        List<AuthenticationExecutionInfoRepresentation> execs = executions();
        for (int i = 0; i < execs.size(); i++) {
            if (KeycloakAdminService.IDP_DETECT_EXISTING_BROKER_USER
                .equals(execs.get(i).getProviderId())) {
                return i;
            }
        }
        return -1;
    }

    /** Flat-list position of the "Handle Existing Account" subflow header, or -1. */
    private int handleExistingAccountPosition() {
        List<AuthenticationExecutionInfoRepresentation> execs = executions();
        for (int i = 0; i < execs.size(); i++) {
            AuthenticationExecutionInfoRepresentation e = execs.get(i);
            if (Boolean.TRUE.equals(e.getAuthenticationFlow())
                && e.getDisplayName() != null
                && e.getDisplayName().endsWith("Handle Existing Account")) {
                return i;
            }
        }
        return -1;
    }

    private long detectCount() {
        return executions().stream()
            .filter(e -> KeycloakAdminService.IDP_DETECT_EXISTING_BROKER_USER
                .equals(e.getProviderId()))
            .count();
    }

    private boolean registrationAllowed() {
        Boolean v = admin.realm(realm).toRepresentation().isRegistrationAllowed();
        return Boolean.TRUE.equals(v);
    }

    @Test
    void setInviteOnly_true_appliesFullRecipe() {
        keycloakAdmin.setInviteOnly(realm, true);

        // detect exists, REQUIRED, and runs BEFORE Handle Existing Account.
        assertThat(detectPosition()).isGreaterThanOrEqualTo(0);
        assertThat(requirementByProvider(
            KeycloakAdminService.IDP_DETECT_EXISTING_BROKER_USER)).isEqualTo("REQUIRED");
        assertThat(detectPosition()).isLessThan(handleExistingAccountPosition());

        // create-if-unique DISABLED.
        assertThat(requirementByProvider(
            KeycloakAdminService.IDP_CREATE_USER_IF_UNIQUE)).isEqualTo("DISABLED");

        // Handle Existing Account subflow REQUIRED.
        assertThat(handleExistingAccountRequirement()).isEqualTo("REQUIRED");

        // realm self-registration off.
        assertThat(registrationAllowed()).isFalse();
    }

    @Test
    void setInviteOnly_false_restoresOpenPosture() {
        keycloakAdmin.setInviteOnly(realm, true);
        keycloakAdmin.setInviteOnly(realm, false);

        // detect left in place but DISABLED.
        assertThat(detectPosition()).isGreaterThanOrEqualTo(0);
        assertThat(requirementByProvider(
            KeycloakAdminService.IDP_DETECT_EXISTING_BROKER_USER)).isEqualTo("DISABLED");

        // create-if-unique back to ALTERNATIVE.
        assertThat(requirementByProvider(
            KeycloakAdminService.IDP_CREATE_USER_IF_UNIQUE)).isEqualTo("ALTERNATIVE");

        // Handle Existing Account subflow back to ALTERNATIVE.
        assertThat(handleExistingAccountRequirement()).isEqualTo("ALTERNATIVE");

        // realm self-registration on.
        assertThat(registrationAllowed()).isTrue();
    }

    @Test
    void setInviteOnly_isIdempotent_andDoesNotDoubleAddDetect() {
        keycloakAdmin.setInviteOnly(realm, true);
        keycloakAdmin.setInviteOnly(realm, true);

        // Exactly one detect execution after two true-applications.
        assertThat(detectCount()).isEqualTo(1L);
        assertThat(requirementByProvider(
            KeycloakAdminService.IDP_DETECT_EXISTING_BROKER_USER)).isEqualTo("REQUIRED");
        assertThat(requirementByProvider(
            KeycloakAdminService.IDP_CREATE_USER_IF_UNIQUE)).isEqualTo("DISABLED");
        assertThat(handleExistingAccountRequirement()).isEqualTo("REQUIRED");
        assertThat(detectPosition()).isLessThan(handleExistingAccountPosition());
        assertThat(registrationAllowed()).isFalse();

        keycloakAdmin.setInviteOnly(realm, false);
        keycloakAdmin.setInviteOnly(realm, false);

        // Still exactly one detect execution, now DISABLED.
        assertThat(detectCount()).isEqualTo(1L);
        assertThat(requirementByProvider(
            KeycloakAdminService.IDP_DETECT_EXISTING_BROKER_USER)).isEqualTo("DISABLED");
        assertThat(requirementByProvider(
            KeycloakAdminService.IDP_CREATE_USER_IF_UNIQUE)).isEqualTo("ALTERNATIVE");
        assertThat(handleExistingAccountRequirement()).isEqualTo("ALTERNATIVE");
        assertThat(registrationAllowed()).isTrue();
    }
}
