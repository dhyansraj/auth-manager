package io.mcpmesh.auth.manager.routing;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mcpmesh.auth.manager.domain.audit.AuditEvent;
import io.mcpmesh.auth.manager.domain.audit.AuditResult;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.persistence.AuditEventRepository;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.routing.model.AuthMode;
import io.mcpmesh.auth.manager.routing.model.RoutingConfig;
import io.mcpmesh.auth.manager.routing.model.RoutingRule;
import io.mcpmesh.auth.manager.service.TenantService;
import io.mcpmesh.auth.manager.service.exception.TenantNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@SpringBootTest
@Testcontainers
class RoutingConfigServiceIT {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16");

    @Container
    @ServiceConnection(name = "redis")
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
        .withExposedPorts(6379);

    @MockitoBean KeycloakAdminService keycloakAdmin;

    @Autowired RoutingConfigService service;
    @Autowired TenantService tenants;
    @Autowired TenantRepository tenantRepo;
    @Autowired AuditEventRepository auditRepo;
    @Autowired StringRedisTemplate redisTpl;
    @Autowired ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        auditRepo.deleteAll();
        tenantRepo.deleteAll();
        redisTpl.getConnectionFactory().getConnection().serverCommands().flushAll();
        when(keycloakAdmin.realmExists(anyString())).thenReturn(false);
        when(keycloakAdmin.createRealm(anyString(), anyString())).thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    void defaultFor_uses_conventional_service_names() {
        RoutingConfig cfg = service.defaultFor("acme");

        assertThat(cfg.rules()).extracting(RoutingRule::path)
            .containsExactly("/api/*", "/*");
        assertThat(cfg.targets())
            .containsEntry("backend",  "acme-backend.tenant-acme.svc.cluster.local:8080")
            .containsEntry("frontend", "acme-ui.tenant-acme.svc.cluster.local:80");
    }

    @Test
    void tenant_create_seeds_routing_config_and_publishes_to_redis() throws Exception {
        Tenant t = tenants.create("acme", "Acme Corp", null, null, "tester");

        // DB has the row.
        RoutingConfig stored = service.getForTenant("acme");
        assertThat(stored.rules()).hasSize(2);

        // Redis has the route:<slug> key as serialized JSON.
        String json = redisTpl.opsForValue().get("route:acme");
        assertThat(json).isNotNull();
        JsonNode tree = objectMapper.readTree(json);
        assertThat(tree.get("rules")).isNotNull();
        assertThat(tree.get("rules").size()).isEqualTo(2);
        assertThat(tree.get("targets").get("backend").asText())
            .isEqualTo("acme-backend.tenant-acme.svc.cluster.local:8080");

        // routes.apply audit event emitted (alongside the tenant.create one).
        assertThat(auditRepo.findAll())
            .extracting(AuditEvent::getAction, AuditEvent::getResult)
            .contains(org.assertj.core.groups.Tuple.tuple("routes.apply", AuditResult.SUCCESS));

        assertThat(t.getRoutingConfig()).isNotNull();
    }

    @Test
    void replaceForTenant_updates_db_redis_and_audits() throws Exception {
        tenants.create("bank", "Bank", null, null, "tester");
        auditRepo.deleteAll();  // focus on the next event

        RoutingConfig replacement = new RoutingConfig(
            List.of(
                new RoutingRule("/public/*", AuthMode.PUBLIC,  "frontend"),
                new RoutingRule("/api/*",    AuthMode.REQUIRED, "backend"),
                new RoutingRule("/*",        AuthMode.OPTIONAL, "frontend")
            ),
            Map.of(
                "backend",  "custom-be:8080",
                "frontend", "custom-fe:80"
            )
        );

        RoutingConfig returned = service.replaceForTenant("bank", replacement);

        assertThat(returned.rules()).hasSize(3);
        assertThat(service.getForTenant("bank").rules()).hasSize(3);

        String json = redisTpl.opsForValue().get("route:bank");
        assertThat(json).isNotNull();
        JsonNode tree = objectMapper.readTree(json);
        assertThat(tree.get("rules").size()).isEqualTo(3);
        assertThat(tree.get("targets").get("backend").asText()).isEqualTo("custom-be:8080");

        assertThat(auditRepo.findAll())
            .extracting(AuditEvent::getAction, AuditEvent::getResult)
            .contains(org.assertj.core.groups.Tuple.tuple("routes.apply", AuditResult.SUCCESS));
    }

    @Test
    void deleteForTenant_removes_redis_key() {
        tenants.create("gone", "Gone", null, null, "tester");
        assertThat(redisTpl.hasKey("route:gone")).isTrue();

        service.deleteForTenant("gone");

        assertThat(redisTpl.hasKey("route:gone")).isFalse();
    }

    @Test
    void getForTenant_throws_when_missing() {
        assertThatThrownBy(() -> service.getForTenant("nope"))
            .isInstanceOf(TenantNotFoundException.class);
    }
}
