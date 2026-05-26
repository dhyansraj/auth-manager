package io.mcpmesh.auth.manager.cloudflare;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Cloudflare API credentials + tunnel context. Bound to env vars CF_API_TOKEN,
 * CF_ACCOUNT_ID, CF_TUNNEL_ID. All fields nullable so the property bag can be
 * loaded even when the Secret isn't provisioned (e.g. local dev) — see
 * {@link #isConfigured()}. CloudflareTunnelService skips CF calls + logs a
 * WARN when not configured.
 */
@ConfigurationProperties(prefix = "cloudflare")
public record CloudflareProperties(
    String apiToken,
    String accountId,
    String tunnelId
) {
    public boolean isConfigured() {
        return apiToken != null && !apiToken.isBlank()
            && accountId != null && !accountId.isBlank()
            && tunnelId != null && !tunnelId.isBlank();
    }
}
