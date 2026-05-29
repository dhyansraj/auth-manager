package io.mcpmesh.auth.manager.email;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Per-realm SMTP defaults applied to every tenant Keycloak realm by
 * {@link SmtpConfigBootstrap}. Bound under {@code auth-manager.smtp.*}.
 *
 * <p>Defaults point at the in-cluster {@code smtp-relay} service which
 * forwards to SendGrid using the platform API key. The relay listens on
 * unauthenticated SMTP :25 — the cluster is the trust boundary; tenants
 * authenticating to the relay would buy us nothing.
 *
 * <p>{@link #enabled()} gates the bootstrap entirely; set to false in
 * environments where KC realms should retain their seeded SMTP config (e.g.
 * the local-dev MailHog setup).
 */
@ConfigurationProperties("auth-manager.smtp")
public record SmtpProperties(
    String host,
    Integer port,
    String fromAddress,
    String fromDisplayNameTemplate,
    Boolean enabled
) {
    public SmtpProperties {
        if (host == null || host.isBlank()) {
            host = "smtp-relay.auth-platform.svc.cluster.local";
        }
        if (port == null) port = 25;
        if (fromAddress == null || fromAddress.isBlank()) {
            fromAddress = "noreply@mcp-mesh.io";
        }
        if (fromDisplayNameTemplate == null || fromDisplayNameTemplate.isBlank()) {
            fromDisplayNameTemplate = "{tenantDisplayName}";
        }
        if (enabled == null) enabled = Boolean.TRUE;
    }

    public boolean isEnabled() {
        return Boolean.TRUE.equals(enabled);
    }

    public String getHost() { return host; }
    public int getPort() { return port; }
    public String getFromAddress() { return fromAddress; }
    public String getFromDisplayNameTemplate() { return fromDisplayNameTemplate; }
}
