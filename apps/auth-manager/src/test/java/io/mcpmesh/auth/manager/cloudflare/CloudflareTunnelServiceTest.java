package io.mcpmesh.auth.manager.cloudflare;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Pure Mockito tests for {@link CloudflareTunnelService}. No CF or k8s touched.
 * Validates the orchestration logic: when to upsert DNS, when to mutate tunnel
 * ingress, and when to skip everything (unconfigured / unknown zone).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CloudflareTunnelServiceTest {

    private static final String ACCOUNT_ID = "acct-123";
    private static final String TUNNEL_ID = "tun-9af0";
    private static final String API_TOKEN = "cfut_test";
    private static final String TENANT_SLUG = "phase2cftest";

    @Mock CloudflareClient cf;
    @Mock CloudflaredReloader reloader;

    CloudflareProperties props;
    CloudflareTunnelService service;

    @BeforeEach
    void setUp() {
        props = new CloudflareProperties(API_TOKEN, ACCOUNT_ID, TUNNEL_ID);
        service = new CloudflareTunnelService(props, cf, reloader);
    }

    @Test
    void deriveZoneName_mcpMeshSubdomain_returnsMcpMesh() {
        assertThat(CloudflareTunnelService.deriveZoneName("safesound-dev.mcp-mesh.io"))
            .isEqualTo("mcp-mesh.io");
    }

    @Test
    void deriveZoneName_apexDomain_returnsItself() {
        assertThat(CloudflareTunnelService.deriveZoneName("safeandsoundhouses.com"))
            .isEqualTo("safeandsoundhouses.com");
    }

    @Test
    void deriveZoneName_wwwSubdomain_returnsApex() {
        assertThat(CloudflareTunnelService.deriveZoneName("www.safeandsoundhouses.com"))
            .isEqualTo("safeandsoundhouses.com");
    }

    @Test
    void isMcpMeshSubdomain_truthTable() {
        assertThat(CloudflareTunnelService.isMcpMeshSubdomain("auth.mcp-mesh.io")).isTrue();
        assertThat(CloudflareTunnelService.isMcpMeshSubdomain("mcp-mesh.io")).isTrue();
        assertThat(CloudflareTunnelService.isMcpMeshSubdomain("foo.bar.mcp-mesh.io")).isTrue();
        assertThat(CloudflareTunnelService.isMcpMeshSubdomain("safeandsoundhouses.com")).isFalse();
        assertThat(CloudflareTunnelService.isMcpMeshSubdomain("www.example.org")).isFalse();
    }

    @Test
    void ensureHostname_mcpMeshSubdomain_upsertsCnameButNotIngress() {
        when(cf.findZoneId("mcp-mesh.io")).thenReturn(Optional.of("zone-mcp"));
        when(cf.findCnameRecordId(eq("zone-mcp"), anyString())).thenReturn(Optional.empty());

        service.ensureHostname("phase2cftest.mcp-mesh.io", TENANT_SLUG);

        verify(cf).createCnameRecord(
            eq("zone-mcp"),
            eq("phase2cftest.mcp-mesh.io"),
            eq(TUNNEL_ID + ".cfargotunnel.com"),
            eq("auth-platform tenant " + TENANT_SLUG));
        verify(cf, never()).getTunnelIngress();
        verify(cf, never()).putTunnelIngress(any());
        verifyNoInteractions(reloader);
    }

    @Test
    void ensureHostname_mcpMeshSubdomain_existingCname_updatesIt() {
        when(cf.findZoneId("mcp-mesh.io")).thenReturn(Optional.of("zone-mcp"));
        when(cf.findCnameRecordId(eq("zone-mcp"), eq("phase2cftest.mcp-mesh.io")))
            .thenReturn(Optional.of("rec-1"));

        service.ensureHostname("phase2cftest.mcp-mesh.io", TENANT_SLUG);

        verify(cf).updateCnameRecord(
            eq("zone-mcp"),
            eq("rec-1"),
            eq("phase2cftest.mcp-mesh.io"),
            eq(TUNNEL_ID + ".cfargotunnel.com"),
            eq("auth-platform tenant " + TENANT_SLUG));
        verify(cf, never()).createCnameRecord(anyString(), anyString(), anyString(), anyString());
        verify(cf, never()).getTunnelIngress();
    }

    @Test
    void ensureHostname_customDomain_zoneInAccount_upsertsCnameAndIngressAndReloads() {
        when(cf.findZoneId("custom.com")).thenReturn(Optional.of("zone-cust"));
        when(cf.findCnameRecordId(eq("zone-cust"), eq("custom.com"))).thenReturn(Optional.empty());
        when(cf.getTunnelIngress()).thenReturn(List.of(
            new CloudflareClient.IngressRule("auth.mcp-mesh.io", "http://edge"),
            new CloudflareClient.IngressRule("*.mcp-mesh.io", "http://edge"),
            new CloudflareClient.IngressRule(null, "http_status:404")
        ));

        service.ensureHostname("custom.com", TENANT_SLUG);

        verify(cf).createCnameRecord(eq("zone-cust"), eq("custom.com"), anyString(), anyString());

        ArgumentCaptor<List<CloudflareClient.IngressRule>> cap = ArgumentCaptor.forClass(List.class);
        verify(cf).putTunnelIngress(cap.capture());
        List<CloudflareClient.IngressRule> written = cap.getValue();
        // Expected order: auth.mcp-mesh.io, custom.com (inserted before wildcard),
        // *.mcp-mesh.io, catch-all.
        assertThat(written).hasSize(4);
        assertThat(written.get(0).hostname()).isEqualTo("auth.mcp-mesh.io");
        assertThat(written.get(1).hostname()).isEqualTo("custom.com");
        assertThat(written.get(2).hostname()).isEqualTo("*.mcp-mesh.io");
        assertThat(written.get(3).hostname()).isNull();
        assertThat(written.get(3).service()).isEqualTo("http_status:404");

        verify(reloader).reloadCloudflared();
    }

    @Test
    void ensureHostname_customDomain_alreadyInIngress_noReload() {
        when(cf.findZoneId("custom.com")).thenReturn(Optional.of("zone-cust"));
        when(cf.findCnameRecordId(eq("zone-cust"), eq("custom.com"))).thenReturn(Optional.of("rec-1"));
        when(cf.getTunnelIngress()).thenReturn(List.of(
            new CloudflareClient.IngressRule("auth.mcp-mesh.io", "http://edge"),
            new CloudflareClient.IngressRule("custom.com", "http://edge"),
            new CloudflareClient.IngressRule("*.mcp-mesh.io", "http://edge"),
            new CloudflareClient.IngressRule(null, "http_status:404")
        ));

        service.ensureHostname("custom.com", TENANT_SLUG);

        verify(cf).updateCnameRecord(anyString(), anyString(), anyString(), anyString(), anyString());
        verify(cf, never()).putTunnelIngress(any());
        verifyNoInteractions(reloader);
    }

    @Test
    void ensureHostname_zoneNotInAccount_logsWarn_noCalls() {
        when(cf.findZoneId("custom.com")).thenReturn(Optional.empty());

        service.ensureHostname("custom.com", TENANT_SLUG);

        verify(cf).findZoneId("custom.com");
        verify(cf, never()).createCnameRecord(anyString(), anyString(), anyString(), anyString());
        verify(cf, never()).updateCnameRecord(anyString(), anyString(), anyString(), anyString(), anyString());
        verify(cf, never()).getTunnelIngress();
        verify(cf, never()).putTunnelIngress(any());
        verifyNoInteractions(reloader);
    }

    @Test
    void removeHostname_mcpMeshSubdomain_deletesCnameOnly() {
        when(cf.findZoneId("mcp-mesh.io")).thenReturn(Optional.of("zone-mcp"));
        when(cf.findCnameRecordId(eq("zone-mcp"), eq("phase2cftest.mcp-mesh.io")))
            .thenReturn(Optional.of("rec-1"));

        service.removeHostname("phase2cftest.mcp-mesh.io", TENANT_SLUG);

        verify(cf).deleteDnsRecord("zone-mcp", "rec-1");
        verify(cf, never()).getTunnelIngress();
        verify(cf, never()).putTunnelIngress(any());
        verifyNoInteractions(reloader);
    }

    @Test
    void removeHostname_customDomain_deletesCnameAndIngressAndReloads() {
        when(cf.findZoneId("custom.com")).thenReturn(Optional.of("zone-cust"));
        when(cf.findCnameRecordId(eq("zone-cust"), eq("custom.com"))).thenReturn(Optional.of("rec-1"));
        when(cf.getTunnelIngress()).thenReturn(List.of(
            new CloudflareClient.IngressRule("auth.mcp-mesh.io", "http://edge"),
            new CloudflareClient.IngressRule("custom.com", "http://edge"),
            new CloudflareClient.IngressRule("*.mcp-mesh.io", "http://edge"),
            new CloudflareClient.IngressRule(null, "http_status:404")
        ));

        service.removeHostname("custom.com", TENANT_SLUG);

        verify(cf).deleteDnsRecord("zone-cust", "rec-1");

        ArgumentCaptor<List<CloudflareClient.IngressRule>> cap = ArgumentCaptor.forClass(List.class);
        verify(cf).putTunnelIngress(cap.capture());
        List<CloudflareClient.IngressRule> written = cap.getValue();
        assertThat(written).hasSize(3);
        assertThat(written).extracting(CloudflareClient.IngressRule::hostname)
            .containsExactly("auth.mcp-mesh.io", "*.mcp-mesh.io", null);

        verify(reloader).reloadCloudflared();
    }

    @Test
    void removeHostname_customDomain_notInIngress_noReload() {
        when(cf.findZoneId("custom.com")).thenReturn(Optional.of("zone-cust"));
        when(cf.findCnameRecordId(eq("zone-cust"), eq("custom.com"))).thenReturn(Optional.empty());
        when(cf.getTunnelIngress()).thenReturn(List.of(
            new CloudflareClient.IngressRule("auth.mcp-mesh.io", "http://edge"),
            new CloudflareClient.IngressRule("*.mcp-mesh.io", "http://edge"),
            new CloudflareClient.IngressRule(null, "http_status:404")
        ));

        service.removeHostname("custom.com", TENANT_SLUG);

        verify(cf, never()).deleteDnsRecord(anyString(), anyString());
        verify(cf, never()).putTunnelIngress(any());
        verifyNoInteractions(reloader);
    }

    @Test
    void ensureHostname_notConfigured_noOp() {
        var unconfigured = new CloudflareTunnelService(
            new CloudflareProperties(null, null, null), cf, reloader);

        unconfigured.ensureHostname("phase2cftest.mcp-mesh.io", TENANT_SLUG);

        verifyNoInteractions(cf);
        verifyNoInteractions(reloader);
    }

    @Test
    void removeHostname_notConfigured_noOp() {
        var unconfigured = new CloudflareTunnelService(
            new CloudflareProperties("", "", ""), cf, reloader);

        unconfigured.removeHostname("phase2cftest.mcp-mesh.io", TENANT_SLUG);

        verifyNoInteractions(cf);
        verifyNoInteractions(reloader);
    }

    @Test
    void ensureHostname_cfFailure_doesNotPropagate() {
        when(cf.findZoneId(anyString())).thenThrow(new RuntimeException("network down"));

        // Must NOT throw — tenant creation must not be blocked by CF outages.
        service.ensureHostname("phase2cftest.mcp-mesh.io", TENANT_SLUG);

        verifyNoInteractions(reloader);
    }

}
