package io.mcpmesh.auth.manager.app;

import io.mcpmesh.auth.manager.domain.app.App;
import io.mcpmesh.auth.manager.domain.audit.AuditEvent;
import io.mcpmesh.auth.manager.domain.audit.AuditResult;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.persistence.AppRepository;
import io.mcpmesh.auth.manager.persistence.AuditEventRepository;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.routing.RoutingConfigService;
import io.mcpmesh.auth.manager.routing.RoutingTableService;
import io.mcpmesh.auth.manager.routing.model.AuthMode;
import io.mcpmesh.auth.manager.routing.model.RoutingConfig;
import io.mcpmesh.auth.manager.routing.model.RoutingRule;
import io.mcpmesh.auth.manager.service.AppService;
import io.mcpmesh.auth.manager.service.TenantService;
import io.mcpmesh.auth.manager.service.exception.AppConflictException;
import io.mcpmesh.auth.manager.service.exception.AppNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@SpringBootTest(properties = {
    "spring.autoconfigure.exclude=" +
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration," +
        "org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration"
})
@Testcontainers
class AppServiceIT {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16");

    @MockitoBean KeycloakAdminService keycloakAdmin;
    @MockitoBean RoutingTableService routingTable;
    @MockitoBean RoutingConfigService routingConfigService;

    @Autowired TenantService tenants;
    @Autowired AppService apps;
    @Autowired TenantRepository tenantRepo;
    @Autowired AppRepository appRepo;
    @Autowired AuditEventRepository auditRepo;

    Tenant tenant;

    @BeforeEach
    void setUp() {
        appRepo.deleteAll();
        tenantRepo.deleteAll();
        auditRepo.deleteAll();
        when(keycloakAdmin.realmExists(anyString())).thenReturn(false);
        when(keycloakAdmin.createRealm(anyString(), anyString())).thenAnswer(inv -> inv.getArgument(0));
        when(keycloakAdmin.findClientUuid(anyString(), anyString())).thenReturn(Optional.empty());
        when(keycloakAdmin.createClient(anyString(), anyString(), anyString())).thenReturn("kc-uuid-123");
        when(keycloakAdmin.getClientSecret(anyString(), anyString())).thenReturn("test-secret");
        when(routingConfigService.defaultFor(anyString())).thenAnswer(inv -> sampleConfig(inv.getArgument(0)));
        when(routingConfigService.replaceForTenant(anyString(), org.mockito.ArgumentMatchers.any()))
            .thenAnswer(inv -> inv.getArgument(1));
        tenant = tenants.create("acme", "Acme Corp", null, null, "tester");
    }

    private static RoutingConfig sampleConfig(String slug) {
        return new RoutingConfig(
            java.util.List.of(new RoutingRule("/*", AuthMode.OPTIONAL, "frontend")),
            java.util.Map.of("frontend", slug + "-ui:80")
        );
    }

    @Test
    void create_persists_app_and_returns_secret() {
        var result = apps.create(tenant.getId(), "orders", "Orders Service", "tester");

        assertThat(result.app().getId()).isNotNull();
        assertThat(result.app().getTenantId()).isEqualTo(tenant.getId());
        assertThat(result.app().getSlug()).isEqualTo("orders");
        assertThat(result.app().getClientId()).isEqualTo("orders");
        assertThat(result.clientSecret()).isEqualTo("test-secret");

        assertThat(auditRepo.findAll())
            .extracting(AuditEvent::getAction, AuditEvent::getResult)
            .contains(org.assertj.core.groups.Tuple.tuple("app.create", AuditResult.SUCCESS));
    }

    @Test
    void create_rejects_duplicate_slug() {
        apps.create(tenant.getId(), "orders", "Orders", "tester");

        assertThatThrownBy(() -> apps.create(tenant.getId(), "orders", "Orders Two", "tester"))
            .isInstanceOf(AppConflictException.class);

        assertThat(auditRepo.findAll())
            .extracting(AuditEvent::getAction, AuditEvent::getResult)
            .contains(org.assertj.core.groups.Tuple.tuple("app.create", AuditResult.FAILURE));
    }

    @Test
    void get_throws_when_missing() {
        assertThatThrownBy(() -> apps.get(tenant.getId(), UUID.randomUUID()))
            .isInstanceOf(AppNotFoundException.class);
    }

    @Test
    void list_returns_apps_for_tenant() {
        apps.create(tenant.getId(), "orders",   "Orders",   "tester");
        apps.create(tenant.getId(), "invoices", "Invoices", "tester");

        var list = apps.listByTenant(tenant.getId());
        assertThat(list).extracting(App::getSlug).containsExactlyInAnyOrder("orders", "invoices");
    }

    @Test
    void delete_removes_app_and_audits() {
        var result = apps.create(tenant.getId(), "orders", "Orders", "tester");
        apps.delete(tenant.getId(), result.app().getId(), "tester");

        assertThatThrownBy(() -> apps.get(tenant.getId(), result.app().getId()))
            .isInstanceOf(AppNotFoundException.class);
        assertThat(auditRepo.findAll())
            .extracting(AuditEvent::getAction)
            .contains("app.delete");
    }
}
