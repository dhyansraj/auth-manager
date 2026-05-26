package io.mcpmesh.auth.manager.cloudflare;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Orchestrates idempotent ensure/remove of Cloudflare resources for tenant
 * hostnames. Called from {@code TenantService} on create + delete.
 *
 * <p>For each hostname:
 * <ul>
 *   <li>Ensure DNS CNAME pointing at {@code <tunnelId>.cfargotunnel.com},
 *       proxied. Only possible if the hostname's apex zone is in our CF
 *       account; otherwise the operator must CNAME manually (we log).</li>
 *   <li>For NON-mcp-mesh.io hostnames, add a tunnel ingress entry pointing at
 *       platform-edge — the static {@code *.mcp-mesh.io} wildcard already
 *       covers mcp-mesh.io subdomains.</li>
 *   <li>When tunnel ingress changes, roll cloudflared so it picks it up.</li>
 * </ul>
 *
 * <p>All CF errors are caught and logged at WARN; tenant DB state is the
 * source of truth so we never block tenant create/delete on CF failures.
 */
@Service
public class CloudflareTunnelService {

    private static final Logger log = LoggerFactory.getLogger(CloudflareTunnelService.class);
    private static final String MCP_MESH_DOMAIN = "mcp-mesh.io";
    private static final String PLATFORM_EDGE_SERVICE =
        "http://auth-platform-platform-edge.auth-platform.svc.cluster.local:80";

    private final CloudflareProperties props;
    private final CloudflareClient cf;
    private final CloudflaredReloader reloader;

    public CloudflareTunnelService(CloudflareProperties props, CloudflareClient cf, CloudflaredReloader reloader) {
        this.props = props;
        this.cf = cf;
        this.reloader = reloader;
    }

    /**
     * Idempotently provisions Cloudflare resources for the given hostname:
     *  - DNS CNAME if hostname's zone is in our CF account
     *  - Tunnel ingress entry if hostname is NOT under mcp-mesh.io (wildcard covers those)
     * Triggers cloudflared rollout if tunnel ingress changed.
     *
     * Best-effort: if CF not configured (no creds), logs WARN and returns.
     * If zone not in our account, logs WARN with copy-pasteable manual steps.
     */
    public void ensureHostname(String hostname, String tenantSlug) {
        if (!props.isConfigured()) {
            log.warn("CloudflareTunnelService: not configured (CF_API_TOKEN etc. unset) — skipping ensureHostname({})", hostname);
            return;
        }
        try {
            String zoneName = deriveZoneName(hostname);
            Optional<String> zoneId = cf.findZoneId(zoneName);
            if (zoneId.isEmpty()) {
                log.warn("CloudflareTunnelService: zone '{}' not in our CF account — operator must manually CNAME '{}' to {}.cfargotunnel.com",
                    zoneName, hostname, props.tunnelId());
                return;
            }
            String tunnelTarget = props.tunnelId() + ".cfargotunnel.com";
            String comment = "auth-platform tenant " + tenantSlug;
            Optional<String> recordId = cf.findCnameRecordId(zoneId.get(), hostname);
            if (recordId.isEmpty()) {
                cf.createCnameRecord(zoneId.get(), hostname, tunnelTarget, comment);
                log.info("CloudflareTunnelService: created CNAME {} -> {} (tenant {})", hostname, tunnelTarget, tenantSlug);
            } else {
                cf.updateCnameRecord(zoneId.get(), recordId.get(), hostname, tunnelTarget, comment);
                log.info("CloudflareTunnelService: refreshed CNAME {} -> {} (tenant {})", hostname, tunnelTarget, tenantSlug);
            }
            if (!isMcpMeshSubdomain(hostname)) {
                boolean changed = ensureIngressEntry(hostname);
                if (changed) {
                    reloader.reloadCloudflared();
                }
            }
        } catch (Exception e) {
            log.warn("CloudflareTunnelService.ensureHostname({}) failed: {} — continuing", hostname, e.getMessage());
        }
    }

    /** Inverse of ensureHostname. Removes CNAME + ingress entry. Best-effort. */
    public void removeHostname(String hostname, String tenantSlug) {
        if (!props.isConfigured()) {
            log.warn("CloudflareTunnelService: not configured — skipping removeHostname({})", hostname);
            return;
        }
        try {
            String zoneName = deriveZoneName(hostname);
            Optional<String> zoneId = cf.findZoneId(zoneName);
            if (zoneId.isPresent()) {
                cf.findCnameRecordId(zoneId.get(), hostname).ifPresent(rid -> {
                    cf.deleteDnsRecord(zoneId.get(), rid);
                    log.info("CloudflareTunnelService: deleted CNAME {} (tenant {})", hostname, tenantSlug);
                });
            }
            if (!isMcpMeshSubdomain(hostname)) {
                boolean changed = removeIngressEntry(hostname);
                if (changed) {
                    reloader.reloadCloudflared();
                }
            }
        } catch (Exception e) {
            log.warn("CloudflareTunnelService.removeHostname({}) failed: {} — continuing", hostname, e.getMessage());
        }
    }

    /** Returns the zone-name (apex) for the given hostname. Simple suffix logic. */
    static String deriveZoneName(String hostname) {
        if (hostname.endsWith("." + MCP_MESH_DOMAIN) || hostname.equals(MCP_MESH_DOMAIN)) {
            return MCP_MESH_DOMAIN;
        }
        String[] parts = hostname.split("\\.");
        if (parts.length < 2) return hostname;
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    static boolean isMcpMeshSubdomain(String hostname) {
        return hostname.endsWith("." + MCP_MESH_DOMAIN) || hostname.equals(MCP_MESH_DOMAIN);
    }

    private boolean ensureIngressEntry(String hostname) {
        List<CloudflareClient.IngressRule> current = cf.getTunnelIngress();
        for (var r : current) {
            if (hostname.equals(r.hostname())) return false;
        }
        // Insert before the first wildcard or catch-all (hostname=null).
        List<CloudflareClient.IngressRule> updated = new ArrayList<>();
        boolean inserted = false;
        for (var r : current) {
            if (!inserted && (r.hostname() == null || r.hostname().startsWith("*."))) {
                updated.add(new CloudflareClient.IngressRule(hostname, PLATFORM_EDGE_SERVICE));
                inserted = true;
            }
            updated.add(r);
        }
        if (!inserted) {
            updated.add(new CloudflareClient.IngressRule(hostname, PLATFORM_EDGE_SERVICE));
        }
        cf.putTunnelIngress(updated);
        log.info("CloudflareTunnelService: added tunnel ingress for {}", hostname);
        return true;
    }

    private boolean removeIngressEntry(String hostname) {
        List<CloudflareClient.IngressRule> current = cf.getTunnelIngress();
        List<CloudflareClient.IngressRule> updated = current.stream()
            .filter(r -> !hostname.equals(r.hostname()))
            .toList();
        if (updated.size() == current.size()) return false;
        cf.putTunnelIngress(updated);
        log.info("CloudflareTunnelService: removed tunnel ingress for {}", hostname);
        return true;
    }
}
