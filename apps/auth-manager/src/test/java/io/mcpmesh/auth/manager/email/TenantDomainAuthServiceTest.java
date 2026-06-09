package io.mcpmesh.auth.manager.email;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.cloudflare.CloudflareClient;
import io.mcpmesh.auth.manager.cloudflare.CloudflareProperties;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.service.TenantService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TenantDomainAuthService}. Stubs SendGridClient +
 * CloudflareClient. Validates the new-domain happy path, conflict fallback,
 * CF-zone-not-in-account graceful path, and the cached status() path.
 */
class TenantDomainAuthServiceTest {

    private static final UUID TENANT_ID = UUID.fromString("00000000-0000-0000-0000-000000000099");
    private static final String SLUG = "app1";

    TenantService tenants;
    TenantRepository repo;
    SendGridClient sendgrid;
    CloudflareClient cf;
    CloudflareProperties cfProps;
    AuditService audit;

    TenantDomainAuthService service;
    Tenant tenant;

    @BeforeEach
    void setUp() {
        tenants = mock(TenantService.class);
        repo = mock(TenantRepository.class);
        sendgrid = mock(SendGridClient.class);
        cf = mock(CloudflareClient.class);
        cfProps = new CloudflareProperties("token", "acct", "tun");
        audit = mock(AuditService.class);
        service = new TenantDomainAuthService(tenants, repo, sendgrid, cf, cfProps, audit);

        tenant = newTenant(SLUG, "App 1");
        when(tenants.get(TENANT_ID)).thenReturn(tenant);
        when(sendgrid.isConfigured()).thenReturn(true);
    }

    @Test
    void start_newDomain_callsSendgridAndCf_storesId() {
        when(sendgrid.createDomain("example.com")).thenReturn(
            new SendGridClient.DomainAuthResult(101, "example.com", false, List.of(
                new SendGridClient.DnsCname("em1234.example.com", "u1234.wl.sendgrid.net"),
                new SendGridClient.DnsCname("s1._domainkey.example.com", "s1.domainkey.u1234.wl.sendgrid.net"),
                new SendGridClient.DnsCname("s2._domainkey.example.com", "s2.domainkey.u1234.wl.sendgrid.net")
            ))
        );
        when(cf.findZoneId("example.com")).thenReturn(Optional.of("zone-ex"));
        when(cf.findCnameRecordId(eq("zone-ex"), anyString())).thenReturn(Optional.empty());
        when(sendgrid.validateDomain(101)).thenReturn(
            new SendGridClient.DomainAuthResult(101, "example.com", true, List.of())
        );

        DomainAuthResponse resp = service.start(TENANT_ID, "example.com", "alice");

        assertThat(resp.domain()).isEqualTo("example.com");
        assertThat(resp.sendgridDomainId()).isEqualTo(101);
        assertThat(resp.valid()).isTrue();
        assertThat(resp.zoneInOurAccount()).isTrue();
        assertThat(resp.cnames()).hasSize(3);
        assertThat(resp.cnames()).allMatch(DomainAuthResponse.CnameRecord::pushed);

        verify(sendgrid).createDomain("example.com");
        verify(cf, times(3)).createDnsOnlyCnameRecord(eq("zone-ex"), anyString(), anyString(), anyString());
        verify(sendgrid).validateDomain(101);
        verify(repo, atLeastOnce()).save(tenant);
        assertThat(tenant.getSendgridDomainId()).isEqualTo(101);
        assertThat(tenant.getSendgridDomainValid()).isTrue();
    }

    @Test
    void start_alreadyRegistered_fallsBackToFind() {
        when(sendgrid.createDomain("example.com"))
            .thenThrow(new SendGridClient.SendGridConflictException("already registered"));
        when(sendgrid.findDomain("example.com")).thenReturn(Optional.of(
            new SendGridClient.DomainAuthResult(202, "example.com", true, List.of(
                new SendGridClient.DnsCname("em.example.com", "u.wl.sendgrid.net")
            ))
        ));
        when(cf.findZoneId("example.com")).thenReturn(Optional.of("zone-ex"));
        when(cf.findCnameRecordId(anyString(), anyString())).thenReturn(Optional.of("rec-existing"));
        when(sendgrid.validateDomain(202)).thenReturn(
            new SendGridClient.DomainAuthResult(202, "example.com", true, List.of())
        );

        DomainAuthResponse resp = service.start(TENANT_ID, "example.com", "alice");

        verify(sendgrid).findDomain("example.com");
        // existing CNAME → don't create
        verify(cf, never()).createDnsOnlyCnameRecord(anyString(), anyString(), anyString(), anyString());
        assertThat(resp.sendgridDomainId()).isEqualTo(202);
        assertThat(resp.valid()).isTrue();
        assertThat(tenant.getSendgridDomainId()).isEqualTo(202);
    }

    @Test
    void start_cfZoneNotInOurAccount_returnsManualCnames() {
        when(sendgrid.createDomain("custom.io")).thenReturn(
            new SendGridClient.DomainAuthResult(303, "custom.io", false, List.of(
                new SendGridClient.DnsCname("em.custom.io", "u.wl.sendgrid.net"),
                new SendGridClient.DnsCname("s1._domainkey.custom.io", "s1.dk.sendgrid.net"),
                new SendGridClient.DnsCname("s2._domainkey.custom.io", "s2.dk.sendgrid.net")
            ))
        );
        when(cf.findZoneId("custom.io")).thenReturn(Optional.empty());
        when(sendgrid.validateDomain(303)).thenReturn(
            new SendGridClient.DomainAuthResult(303, "custom.io", false, List.of())
        );

        DomainAuthResponse resp = service.start(TENANT_ID, "custom.io", "alice");

        assertThat(resp.zoneInOurAccount()).isFalse();
        assertThat(resp.valid()).isFalse();
        assertThat(resp.cnames()).hasSize(3);
        assertThat(resp.cnames()).allMatch(c -> !c.pushed() && c.pushError() != null);
        verify(cf, never()).createDnsOnlyCnameRecord(anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void status_readsCachedRowAndRequeriesSendgrid() {
        tenant.setSendgridDomain(404, false);
        Map_setSendgridSettings(tenant, "example.com");
        when(sendgrid.getDomain(404)).thenReturn(
            new SendGridClient.DomainAuthResult(404, "example.com", true, List.of(
                new SendGridClient.DnsCname("em.example.com", "u.wl.sendgrid.net")
            ))
        );
        when(cf.findZoneId("example.com")).thenReturn(Optional.of("zone-ex"));

        DomainAuthResponse resp = service.status(TENANT_ID);

        assertThat(resp.sendgridDomainId()).isEqualTo(404);
        assertThat(resp.valid()).isTrue();
        assertThat(tenant.getSendgridDomainValid()).isTrue();
        verify(sendgrid).getDomain(404);
        verify(sendgrid, never()).createDomain(anyString());
        // The valid flag changed (false → true) so a save() happens.
        verify(repo, atLeastOnce()).save(tenant);
    }

    @Test
    void revalidate_validTrue_persistsFlagTrue() {
        tenant.setSendgridDomain(505, false);
        Map_setSendgridSettings(tenant, "example.com");
        when(sendgrid.validateDomain(505)).thenReturn(
            new SendGridClient.DomainAuthResult(505, "example.com", true, List.of(
                new SendGridClient.DnsCname("em.example.com", "u.wl.sendgrid.net")
            ))
        );
        when(cf.findZoneId("example.com")).thenReturn(Optional.of("zone-ex"));

        DomainAuthResponse resp = service.revalidate(TENANT_ID, "alice");

        assertThat(resp.valid()).isTrue();
        assertThat(resp.sendgridDomainId()).isEqualTo(505);
        // Root-cause check: the valid flag is persisted as true on the tenant row.
        assertThat(tenant.getSendgridDomainValid()).isTrue();
        verify(sendgrid).validateDomain(505);
        verify(repo, atLeastOnce()).save(tenant);
    }

    @Test
    void revalidate_validFalse_persistsFlagFalse() {
        tenant.setSendgridDomain(505, true);
        when(sendgrid.validateDomain(505)).thenReturn(
            new SendGridClient.DomainAuthResult(505, "example.com", false, List.of())
        );

        DomainAuthResponse resp = service.revalidate(TENANT_ID, "alice");

        assertThat(resp.valid()).isFalse();
        assertThat(tenant.getSendgridDomainValid()).isFalse();
        verify(repo, atLeastOnce()).save(tenant);
    }

    @Test
    void setSendgridDomain_writesValidFlagToEntity() {
        Tenant t = newTenant("ent", "Ent");
        t.setSendgridDomain(606, true);
        assertThat(t.getSendgridDomainId()).isEqualTo(606);
        assertThat(t.getSendgridDomainValid()).isTrue();
    }

    @Test
    void registrableDomain_simpleHelper() {
        assertThat(TenantDomainAuthService.registrableDomain("mail.example.com")).isEqualTo("example.com");
        assertThat(TenantDomainAuthService.registrableDomain("example.com")).isEqualTo("example.com");
        assertThat(TenantDomainAuthService.registrableDomain("a.b.example.com")).isEqualTo("b.example.com");
    }

    // -- helpers --------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static void Map_setSendgridSettings(Tenant t, String domain) {
        java.util.Map<String, Object> settings = t.getSettings();
        java.util.Map<String, Object> sg = new HashMap<>();
        sg.put("domain", domain);
        settings.put("sendgrid", sg);
    }

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
