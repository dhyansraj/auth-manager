package io.mcpmesh.auth.manager.keycloak;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Platform-level OAuth provider credentials. ONE app per provider lives at the
 * provider (Google, GitHub) and is shared by every tenant realm. The realm
 * brokers OAuth via these credentials and Keycloak's built-in
 * {@code google} / {@code github} identity provider templates.
 *
 * <p>The provider creds are bound from a k8s Secret
 * ({@code platform-oauth-providers}) via env vars
 * {@code PLATFORM_OAUTH_GOOGLE_CLIENT_ID}, {@code PLATFORM_OAUTH_GOOGLE_CLIENT_SECRET},
 * {@code PLATFORM_OAUTH_GITHUB_CLIENT_ID}, {@code PLATFORM_OAUTH_GITHUB_CLIENT_SECRET}.
 *
 * <p>If a provider's credentials are unset (env var blank or missing), that
 * provider is considered <em>unavailable</em>: bootstrap skips it, and the
 * admin-ui surfaces a "platform admin must configure first" hint.
 */
@ConfigurationProperties("platform.oauth")
public record PlatformOAuthProperties(
    Provider google,
    Provider github
) {
    public PlatformOAuthProperties {
        if (google == null) google = new Provider(null, null);
        if (github == null) github = new Provider(null, null);
    }

    /** Credentials for a single OAuth provider. {@code blank() == true} when unconfigured. */
    public record Provider(String clientId, String clientSecret) {
        public boolean isConfigured() {
            return clientId != null && !clientId.isBlank()
                && clientSecret != null && !clientSecret.isBlank();
        }
    }

    /**
     * Returns the configured provider creds keyed by provider id ("google" /
     * "github"). Always contains both keys; absent / blank creds surface as
     * {@code !isConfigured()} on the value side.
     */
    public Map<String, Provider> asMap() {
        Map<String, Provider> m = new LinkedHashMap<>();
        m.put("google", google);
        m.put("github", github);
        return m;
    }
}
