package io.mcpmesh.auth.manager.email;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.service.TenantService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TenantEmailService}. Stubs the dependencies
 * (TenantService, repo, SmtpConfigBootstrap, AuditService) so we don't
 * need a running KC or DB. Validates the override-vs-default resolution,
 * input validation, and the KC reconcile wiring.
 */
class TenantEmailServiceTest {

    private static final UUID TENANT_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final String SLUG = "app1";

    TenantService tenants;
    TenantRepository repo;
    SmtpProperties smtpProps;
    SmtpConfigBootstrap bootstrap;
    AuditService audit;
    io.mcpmesh.auth.manager.email.templates.EmailRateLimitProperties rateLimitProps;

    TenantEmailService service;
    Tenant tenant;

    @BeforeEach
    void setUp() {
        tenants = mock(TenantService.class);
        repo = mock(TenantRepository.class);
        smtpProps = new SmtpProperties(
            "smtp-relay.auth-platform.svc.cluster.local",
            25,
            "noreply@mcp-mesh.io",
            "{tenantDisplayName}",
            true,
            "SG.test-key"
        );
        bootstrap = mock(SmtpConfigBootstrap.class);
        audit = mock(AuditService.class);
        rateLimitProps = new io.mcpmesh.auth.manager.email.templates.EmailRateLimitProperties(
            100, 5000, true);
        service = new TenantEmailService(tenants, repo, smtpProps, bootstrap, audit,
            rateLimitProps);

        tenant = newTenant(SLUG, "App 1");
        when(tenants.get(TENANT_ID)).thenReturn(tenant);
    }

    @Test
    void get_returnsPlatformDefault_whenNoOverride() {
        TenantEmailResponse resp = service.get(TENANT_ID);

        assertThat(resp.fromAddress()).isEqualTo("noreply@mcp-mesh.io");
        assertThat(resp.fromAddressOverride()).isNull();
        assertThat(resp.fromDisplayName()).isEqualTo("App 1");
        assertThat(resp.fromDisplayNameOverride()).isNull();
        assertThat(resp.replyToAddress()).isNull();
        assertThat(resp.domainAuthStatus()).isEqualTo(TenantEmailResponse.DomainAuthStatus.NOT_STARTED);
    }

    @Test
    void get_returnsOverride_whenTenantHasFromAddress() {
        tenant.setEmailOverrides("hello@example.com", "Example Hello", "support@example.com");

        TenantEmailResponse resp = service.get(TENANT_ID);

        assertThat(resp.fromAddress()).isEqualTo("hello@example.com");
        assertThat(resp.fromAddressOverride()).isEqualTo("hello@example.com");
        assertThat(resp.fromDisplayName()).isEqualTo("Example Hello");
        assertThat(resp.fromDisplayNameOverride()).isEqualTo("Example Hello");
        assertThat(resp.replyToAddress()).isEqualTo("support@example.com");
    }

    @Test
    void update_rejectsInvalidEmailFormat() {
        var req = new TenantEmailUpdateRequest("not-an-email", null, null);

        assertThatThrownBy(() -> service.update(TENANT_ID, req, "alice"))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("invalid_from_address");

        verify(repo, never()).save(any());
        verify(bootstrap, never()).reconcileRealmSmtp(any());
        verify(audit).recordFailure(anyString(), any(), any(), anyString(),
            anyString(), anyString(), any(), any(), any());
    }

    @Test
    void update_rejectsFromAddressMismatchingAuthenticatedDomain() {
        // Tenant has authenticated example.com (id=42, valid=true) — caller
        // tries to set from = noreply@other.com. Must reject.
        tenant.setSendgridDomain(42, true);
        Map<String, Object> settings = (Map<String, Object>) tenant.getSettings();
        Map<String, Object> sg = new HashMap<>();
        sg.put("domain", "example.com");
        settings.put("sendgrid", sg);

        var req = new TenantEmailUpdateRequest("noreply@other.com", null, null);

        assertThatThrownBy(() -> service.update(TENANT_ID, req, "alice"))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("unauthorized_from_domain");

        verify(repo, never()).save(any());
    }

    @Test
    void update_acceptsFromAddressOnPlatformDomain_evenWithoutTenantSgDomain() {
        // Platform fallback domain (mcp-mesh.io) is always allowed regardless
        // of tenant SG state — operator can leave the platform From + just
        // tweak the display name.
        var req = new TenantEmailUpdateRequest("hello@mcp-mesh.io", "App One", null);

        TenantEmailResponse resp = service.update(TENANT_ID, req, "alice");

        assertThat(resp.fromAddress()).isEqualTo("hello@mcp-mesh.io");
        verify(repo).save(tenant);
        verify(bootstrap).reconcileRealmSmtp(tenant);
    }

    @Test
    void update_success_callsReconcileRealmSmtp() {
        // Authenticate example.com first so the from check passes.
        tenant.setSendgridDomain(42, true);
        Map<String, Object> settings = (Map<String, Object>) tenant.getSettings();
        Map<String, Object> sg = new HashMap<>();
        sg.put("domain", "example.com");
        settings.put("sendgrid", sg);

        var req = new TenantEmailUpdateRequest(
            "hello@example.com", "Hello Bot", "reply@example.com");

        TenantEmailResponse resp = service.update(TENANT_ID, req, "alice");

        assertThat(resp.fromAddress()).isEqualTo("hello@example.com");
        assertThat(resp.fromDisplayName()).isEqualTo("Hello Bot");
        assertThat(resp.replyToAddress()).isEqualTo("reply@example.com");
        verify(repo, times(1)).save(tenant);
        verify(bootstrap, times(1)).reconcileRealmSmtp(tenant);
        verify(audit).recordSuccess(anyString(), any(), any(), anyString(),
            anyString(), anyString(), any(), any());
    }

    // -- rate-limit overrides --------------------------------------------------

    @Test
    void getRateLimit_returnsPlatformDefaults_whenNoOverride() {
        TenantEmailRateLimitResponse resp = service.getRateLimit(TENANT_ID);

        assertThat(resp.perMinute()).isEqualTo(100);
        assertThat(resp.perDay()).isEqualTo(5000);
        assertThat(resp.perMinuteOverride()).isNull();
        assertThat(resp.perDayOverride()).isNull();
        assertThat(resp.platformPerMinute()).isEqualTo(100);
        assertThat(resp.platformPerDay()).isEqualTo(5000);
        assertThat(resp.enabled()).isTrue();
    }

    @Test
    void getRateLimit_returnsOverrides_whenTenantHasThem() {
        tenant.setEmailRateLimitOverrides(10, 200);

        TenantEmailRateLimitResponse resp = service.getRateLimit(TENANT_ID);

        assertThat(resp.perMinute()).isEqualTo(10);
        assertThat(resp.perDay()).isEqualTo(200);
        assertThat(resp.perMinuteOverride()).isEqualTo(10);
        assertThat(resp.perDayOverride()).isEqualTo(200);
        assertThat(resp.platformPerMinute()).isEqualTo(100);
        assertThat(resp.platformPerDay()).isEqualTo(5000);
    }

    @Test
    void updateRateLimit_persistsOverrides_andAudits() {
        var req = new TenantEmailRateLimitUpdateRequest(50, 10_000);

        TenantEmailRateLimitResponse resp = service.updateRateLimit(TENANT_ID, req, "alice");

        assertThat(resp.perMinute()).isEqualTo(50);
        assertThat(resp.perDay()).isEqualTo(10_000);
        assertThat(tenant.getEmailRlPerMinute()).isEqualTo(50);
        assertThat(tenant.getEmailRlPerDay()).isEqualTo(10_000);
        verify(repo).save(tenant);
        verify(audit).recordSuccess(anyString(), any(), any(), anyString(),
            anyString(), anyString(), any(), any());
    }

    @Test
    void updateRateLimit_nullFields_clearOverrides() {
        tenant.setEmailRateLimitOverrides(50, 10_000);

        TenantEmailRateLimitResponse resp = service.updateRateLimit(
            TENANT_ID, new TenantEmailRateLimitUpdateRequest(null, null), "alice");

        assertThat(tenant.getEmailRlPerMinute()).isNull();
        assertThat(tenant.getEmailRlPerDay()).isNull();
        assertThat(resp.perMinute()).isEqualTo(100);   // back to platform default
        assertThat(resp.perDay()).isEqualTo(5000);
        verify(repo).save(tenant);
    }

    @Test
    void updateRateLimit_rejectsNonPositiveValues() {
        var req = new TenantEmailRateLimitUpdateRequest(0, null);

        assertThatThrownBy(() -> service.updateRateLimit(TENANT_ID, req, "alice"))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("invalid_rate_limit");

        verify(repo, never()).save(any());
        verify(audit).recordFailure(anyString(), any(), any(), anyString(),
            anyString(), anyString(), any(), any(), any());
    }

    @Test
    void updateRateLimit_rejectsValuesOverUpperBound() {
        var req = new TenantEmailRateLimitUpdateRequest(null, 100_001);

        assertThatThrownBy(() -> service.updateRateLimit(TENANT_ID, req, "alice"))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("invalid_rate_limit");

        verify(repo, never()).save(any());
    }

    // -- helpers --------------------------------------------------------------

    /**
     * Minimal Tenant entity with id + slug + displayName set via reflection
     * (the no-arg ctor is protected and the public ctor leaves id null).
     */
    private static Tenant newTenant(String slug, String displayName) {
        Tenant t = new Tenant(slug, displayName, "system", new HashMap<>());
        setField(t, "id", TENANT_ID);
        setField(t, "realmName", "t-" + slug);
        return t;
    }

    private static void setField(Object target, String name, Object value) {
        try {
            Field f = target.getClass().getDeclaredField(name);
            f.setAccessible(true);
            f.set(target, value);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }
}
