package io.mcpmesh.auth.manager.app;

import io.mcpmesh.auth.manager.api.dto.CreateAppRequest;
import io.mcpmesh.auth.manager.api.dto.CreateAppRequest.AppProfile;
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

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
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

    private static CreateAppRequest req(String slug, String displayName) {
        return new CreateAppRequest(slug, displayName, AppProfile.CONFIDENTIAL_BACKEND, null);
    }

    @Test
    void create_persists_app_and_returns_secret() {
        var result = apps.create(tenant.getId(), req("orders", "Orders Service"), "tester");

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
        apps.create(tenant.getId(), req("orders", "Orders"), "tester");

        assertThatThrownBy(() -> apps.create(tenant.getId(), req("orders", "Orders Two"), "tester"))
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
        apps.create(tenant.getId(), req("orders",   "Orders"),   "tester");
        apps.create(tenant.getId(), req("invoices", "Invoices"), "tester");

        var list = apps.listByTenant(tenant.getId());
        assertThat(list).extracting(App::getSlug).containsExactlyInAnyOrder("orders", "invoices");
    }

    @Test
    void delete_removes_app_and_audits() {
        var result = apps.create(tenant.getId(), req("orders", "Orders"), "tester");
        apps.delete(tenant.getId(), result.app().getId(), "tester");

        assertThatThrownBy(() -> apps.get(tenant.getId(), result.app().getId()))
            .isInstanceOf(AppNotFoundException.class);
        assertThat(auditRepo.findAll())
            .extracting(AuditEvent::getAction)
            .contains("app.delete");
    }

    // ---- profiles ----------------------------------------------------------

    @Test
    void create_spaPkce_flipsPublicAndSetsPkceAttrAndDisablesServiceAccount() {
        var req = new CreateAppRequest("ui", "UI", AppProfile.SPA_PKCE, null);
        var result = apps.create(tenant.getId(), req, "tester");

        // Public client -> no client_secret should be returned to caller.
        assertThat(result.clientSecret()).isNull();

        String realm = tenant.getRealmName();
        verify(keycloakAdmin).setClientPublic(eq(realm), eq("ui"), eq(true));
        verify(keycloakAdmin).setClientAttributes(eq(realm), eq("kc-uuid-123"),
            org.mockito.ArgumentMatchers.argThat(attrs ->
                "S256".equals(attrs.get("pkce.code.challenge.method"))
                && "false".equals(attrs.get("client.use.lightweight.access.token.enabled"))));
        verify(keycloakAdmin).setStandardRedirectUris(
            eq(realm), eq("kc-uuid-123"), any(), any(), eq(false));
        verify(keycloakAdmin).setClientFlowFlags(
            eq(realm), eq("kc-uuid-123"), eq(true), eq(false), eq(false));
    }

    @Test
    void create_serviceAccountOnly_disablesStandardFlowAndEnablesServiceAccount() {
        var req = new CreateAppRequest("daemon", "Daemon", AppProfile.SERVICE_ACCOUNT_ONLY, null);
        var result = apps.create(tenant.getId(), req, "tester");

        assertThat(result.clientSecret()).isEqualTo("test-secret");
        String realm = tenant.getRealmName();

        verify(keycloakAdmin).setClientFlowFlags(
            eq(realm), eq("kc-uuid-123"),
            eq(false),  // standardFlow off
            eq(false),  // directGrants off
            eq(true));  // serviceAccounts on
        verify(keycloakAdmin).setClientAttributes(eq(realm), eq("kc-uuid-123"),
            org.mockito.ArgumentMatchers.argThat(attrs ->
                "false".equals(attrs.get("client.use.lightweight.access.token.enabled"))));
        // SPA-only mutations should NOT be applied for SERVICE_ACCOUNT_ONLY.
        verify(keycloakAdmin, never()).setClientPublic(anyString(), anyString(), anyBoolean());
    }

    @Test
    void create_confidentialBackend_isNoOpOnProfileMutations() {
        var req = req("orders", "Orders");
        apps.create(tenant.getId(), req, "tester");

        String realm = tenant.getRealmName();
        verify(keycloakAdmin, never()).setClientPublic(eq(realm), eq("orders"), anyBoolean());
        verify(keycloakAdmin, never()).setClientFlowFlags(
            eq(realm), anyString(), anyBoolean(), anyBoolean(), anyBoolean());
    }

    @Test
    void create_audienceList_createsMapperPerEntry_skippingSelfAndBlanks() {
        when(keycloakAdmin.ensureAudienceMapper(anyString(), anyString(), anyString())).thenReturn(true);
        var req = new CreateAppRequest("orders", "Orders",
            AppProfile.CONFIDENTIAL_BACKEND,
            List.of("invoices", "billing", "", "orders" /* self -> skipped */));

        apps.create(tenant.getId(), req, "tester");

        String realm = tenant.getRealmName();
        verify(keycloakAdmin).ensureAudienceMapper(eq(realm), eq("kc-uuid-123"), eq("invoices"));
        verify(keycloakAdmin).ensureAudienceMapper(eq(realm), eq("kc-uuid-123"), eq("billing"));
        verify(keycloakAdmin, never()).ensureAudienceMapper(eq(realm), anyString(), eq("orders"));
        verify(keycloakAdmin, never()).ensureAudienceMapper(eq(realm), anyString(), eq(""));
    }

    @Test
    void create_noAudienceField_skipsMapperCreation() {
        apps.create(tenant.getId(), req("orders", "Orders"), "tester");

        verify(keycloakAdmin, never()).ensureAudienceMapper(anyString(), anyString(), anyString());
    }

    // ---- updateServiceAccountPermissions -----------------------------------

    @Test
    void updateServiceAccountPermissions_addsAndRemovesDiff_andReturnsEffective() {
        var created = apps.create(tenant.getId(), req("orders", "Orders"), "tester");
        UUID appId = created.app().getId();
        String realm = tenant.getRealmName();

        // app client + usermanagement client both resolve
        when(keycloakAdmin.findClientUuid(eq(realm), eq("orders"))).thenReturn(Optional.of("orders-uuid"));
        when(keycloakAdmin.findClientUuid(eq(realm), eq("usermanagement"))).thenReturn(Optional.of("um-uuid"));
        when(keycloakAdmin.findServiceAccountUserId(eq(realm), eq("orders-uuid")))
            .thenReturn(Optional.of("sa-user-id"));
        when(keycloakAdmin.listClientRoleNames(eq(realm), eq("um-uuid")))
            .thenReturn(List.of("USER_LIST", "USER_INVITE", "USER_DISABLE"));
        // current = [USER_DISABLE]; desired = [USER_LIST, USER_INVITE]
        when(keycloakAdmin.getUserClientRoles(eq(realm), eq("sa-user-id"), eq("usermanagement")))
            .thenReturn(List.of("USER_DISABLE"))
            .thenReturn(List.of("USER_INVITE", "USER_LIST"));  // after the diff is applied

        var result = apps.updateServiceAccountPermissions(
            tenant.getId(), appId, Set.of("USER_LIST", "USER_INVITE"), "tester");

        assertThat(result).containsExactly("USER_INVITE", "USER_LIST");
        verify(keycloakAdmin).assignClientRoleToUser(eq(realm), eq("sa-user-id"),
            eq("usermanagement"), eq("USER_LIST"));
        verify(keycloakAdmin).assignClientRoleToUser(eq(realm), eq("sa-user-id"),
            eq("usermanagement"), eq("USER_INVITE"));
        verify(keycloakAdmin).removeClientRoleFromUser(eq(realm), eq("sa-user-id"),
            eq("usermanagement"), eq("USER_DISABLE"));
        assertThat(auditRepo.findAll())
            .extracting(AuditEvent::getAction)
            .contains("app.service_account.permissions.update");
    }

    @Test
    void updateServiceAccountPermissions_rejectsUnknownPermission() {
        var created = apps.create(tenant.getId(), req("orders", "Orders"), "tester");
        UUID appId = created.app().getId();
        String realm = tenant.getRealmName();

        when(keycloakAdmin.findClientUuid(eq(realm), eq("orders"))).thenReturn(Optional.of("orders-uuid"));
        when(keycloakAdmin.findClientUuid(eq(realm), eq("usermanagement"))).thenReturn(Optional.of("um-uuid"));
        when(keycloakAdmin.findServiceAccountUserId(eq(realm), eq("orders-uuid")))
            .thenReturn(Optional.of("sa-user-id"));
        when(keycloakAdmin.listClientRoleNames(eq(realm), eq("um-uuid")))
            .thenReturn(List.of("USER_LIST"));

        assertThatThrownBy(() -> apps.updateServiceAccountPermissions(
            tenant.getId(), appId, Set.of("USER_LIST", "BOGUS_PERM"), "tester"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("BOGUS_PERM");

        verify(keycloakAdmin, never()).assignClientRoleToUser(anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void updateServiceAccountPermissions_failsIfNoServiceAccount() {
        var created = apps.create(tenant.getId(), req("orders", "Orders"), "tester");
        UUID appId = created.app().getId();
        String realm = tenant.getRealmName();

        when(keycloakAdmin.findClientUuid(eq(realm), eq("orders"))).thenReturn(Optional.of("orders-uuid"));
        when(keycloakAdmin.findClientUuid(eq(realm), eq("usermanagement"))).thenReturn(Optional.of("um-uuid"));
        when(keycloakAdmin.findServiceAccountUserId(eq(realm), eq("orders-uuid")))
            .thenReturn(Optional.empty());

        assertThatThrownBy(() -> apps.updateServiceAccountPermissions(
            tenant.getId(), appId, Set.of("USER_LIST"), "tester"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("service account");
    }
}
