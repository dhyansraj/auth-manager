package io.mcpmesh.auth.manager.email;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.mockito.ArgumentCaptor;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SmtpConfigBootstrap}. Stubs the KC admin client; no
 * real server needed. Mirrors the test style of the other bootstrap classes
 * in {@code io.mcpmesh.auth.manager.keycloak}.
 */
class SmtpConfigBootstrapTest {

    private static final String REALM = "t-app1";
    private static final String TENANT_DISPLAY = "App One";

    private Keycloak admin;
    private RealmResource realm;
    private TenantRepository tenantRepo;
    private SmtpProperties props;

    @BeforeEach
    void setUp() {
        admin = mock(Keycloak.class);
        realm = mock(RealmResource.class);
        tenantRepo = mock(TenantRepository.class);
        when(admin.realm(REALM)).thenReturn(realm);

        props = new SmtpProperties(
            "smtp-relay.auth-platform.svc.cluster.local",
            25,
            "noreply@mcp-mesh.io",
            "{tenantDisplayName}",
            Boolean.TRUE
        );
    }

    private Tenant tenantStub() {
        Tenant t = mock(Tenant.class);
        when(t.getRealmName()).thenReturn(REALM);
        when(t.getDisplayName()).thenReturn(TENANT_DISPLAY);
        return t;
    }

    private Map<String, String> desiredFor(Tenant t) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("host", "smtp-relay.auth-platform.svc.cluster.local");
        m.put("port", "25");
        m.put("from", "noreply@mcp-mesh.io");
        m.put("fromDisplayName", t.getDisplayName());
        m.put("auth", "false");
        m.put("starttls", "false");
        m.put("ssl", "false");
        return m;
    }

    @Test
    void reconcileRealmSmtp_sets_expected_smtp_map_when_realm_is_empty() {
        Tenant t = tenantStub();
        RealmRepresentation rep = new RealmRepresentation();
        rep.setSmtpServer(null);
        when(realm.toRepresentation()).thenReturn(rep);

        var bootstrap = new SmtpConfigBootstrap(admin, tenantRepo, props);
        boolean updated = bootstrap.reconcileRealmSmtp(t);

        assertThat(updated).isTrue();
        ArgumentCaptor<RealmRepresentation> cap = ArgumentCaptor.forClass(RealmRepresentation.class);
        verify(realm, times(1)).update(cap.capture());
        Map<String, String> applied = cap.getValue().getSmtpServer();
        assertThat(applied)
            .containsEntry("host", "smtp-relay.auth-platform.svc.cluster.local")
            .containsEntry("port", "25")
            .containsEntry("from", "noreply@mcp-mesh.io")
            .containsEntry("fromDisplayName", TENANT_DISPLAY)
            .containsEntry("auth", "false")
            .containsEntry("starttls", "false")
            .containsEntry("ssl", "false");
        // replyTo is intentionally omitted in Phase 1.
        assertThat(applied).doesNotContainKey("replyTo");
    }

    @Test
    void reconcileRealmSmtp_is_noop_when_already_matches() {
        Tenant t = tenantStub();
        RealmRepresentation rep = new RealmRepresentation();
        rep.setSmtpServer(desiredFor(t));
        when(realm.toRepresentation()).thenReturn(rep);

        var bootstrap = new SmtpConfigBootstrap(admin, tenantRepo, props);
        boolean updated = bootstrap.reconcileRealmSmtp(t);

        assertThat(updated).isFalse();
        verify(realm, never()).update(any());
    }

    @Test
    void buildSmtpConfig_uses_tenant_displayName_for_fromDisplayName() {
        Tenant t = tenantStub();
        var bootstrap = new SmtpConfigBootstrap(admin, tenantRepo, props);

        Map<String, String> cfg = bootstrap.buildSmtpConfig(t);

        assertThat(cfg).containsEntry("fromDisplayName", TENANT_DISPLAY);
    }

    @Test
    void buildSmtpConfig_substitutes_tenantDisplayName_token_in_template() {
        Tenant t = tenantStub();
        SmtpProperties templatedProps = new SmtpProperties(
            null, null, null, "Auth ({tenantDisplayName})", null
        );
        var bootstrap = new SmtpConfigBootstrap(admin, tenantRepo, templatedProps);

        Map<String, String> cfg = bootstrap.buildSmtpConfig(t);

        assertThat(cfg).containsEntry("fromDisplayName", "Auth (" + TENANT_DISPLAY + ")");
    }
}
