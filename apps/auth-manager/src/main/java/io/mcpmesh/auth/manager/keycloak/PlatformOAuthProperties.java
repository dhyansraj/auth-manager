package io.mcpmesh.auth.manager.keycloak;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Platform-level OAuth provider credentials. ONE app per provider lives at the
 * provider (Google, GitHub, Apple) and is shared by every tenant realm. The
 * realm brokers OAuth via these credentials and Keycloak's identity provider
 * instances.
 *
 * <p>The provider creds are bound from a k8s Secret
 * ({@code platform-oauth-providers}) via env vars
 * {@code PLATFORM_OAUTH_GOOGLE_CLIENT_ID}, {@code PLATFORM_OAUTH_GOOGLE_CLIENT_SECRET},
 * {@code PLATFORM_OAUTH_GITHUB_CLIENT_ID}, {@code PLATFORM_OAUTH_GITHUB_CLIENT_SECRET},
 * and for Apple {@code PLATFORM_OAUTH_APPLE_SERVICES_ID},
 * {@code PLATFORM_OAUTH_APPLE_TEAM_ID}, {@code PLATFORM_OAUTH_APPLE_KEY_ID},
 * {@code PLATFORM_OAUTH_APPLE_PRIVATE_KEY}.
 *
 * <p>If a provider's credentials are unset (env var blank or missing), that
 * provider is considered <em>unavailable</em>: bootstrap skips it, and the
 * admin-ui surfaces a "platform admin must configure first" hint.
 *
 * <p>Apple is shaped differently from google/github (it has no static
 * client-secret — the secret is a short-lived ES256 JWT minted from a PKCS8 EC
 * private key), so it is NOT part of {@link #asMap()}. Consume it via
 * {@link #apple()} and handle it separately in bootstrap.
 */
@ConfigurationProperties("platform.oauth")
public record PlatformOAuthProperties(
    Provider google,
    Provider github,
    AppleProvider apple
) {
    public PlatformOAuthProperties {
        if (google == null) google = new Provider(null, null);
        if (github == null) github = new Provider(null, null);
        if (apple == null) apple = new AppleProvider(null, null, null, null);
    }

    /** Credentials for a single OAuth provider. {@code blank() == true} when unconfigured. */
    public record Provider(String clientId, String clientSecret) {
        public boolean isConfigured() {
            return clientId != null && !clientId.isBlank()
                && clientSecret != null && !clientSecret.isBlank();
        }
    }

    /**
     * Apple "Sign in with Apple" credentials. Unlike google/github there is no
     * static client secret: the raw {@code .p8} private key is passed to the
     * Apple SPI as the {@code clientSecret} config value, and the SPI mints the
     * short-lived ES256 JWT from it.
     *
     * <ul>
     *   <li>{@code servicesId} — the Apple "Services ID" identifier; this is the
     *       OIDC {@code client_id}.</li>
     *   <li>{@code teamId} — the 10-char Apple Developer Team ID; the JWT
     *       {@code iss}.</li>
     *   <li>{@code keyId} — the 10-char Key ID for the registered private key;
     *       the JWT header {@code kid}.</li>
     *   <li>{@code privateKey} — the PKCS8 PEM contents of the {@code .p8} key
     *       download.</li>
     * </ul>
     */
    public record AppleProvider(String servicesId, String teamId, String keyId, String privateKey) {
        public boolean isConfigured() {
            return servicesId != null && !servicesId.isBlank()
                && teamId != null && !teamId.isBlank()
                && keyId != null && !keyId.isBlank()
                && privateKey != null && !privateKey.isBlank();
        }
    }

    /**
     * Returns the configured provider creds keyed by provider id ("google" /
     * "github"). Always contains both keys; absent / blank creds surface as
     * {@code !isConfigured()} on the value side.
     *
     * <p>Apple is intentionally excluded — its credential shape differs (see
     * {@link AppleProvider}); use {@link #apple()} directly.
     */
    public Map<String, Provider> asMap() {
        Map<String, Provider> m = new LinkedHashMap<>();
        m.put("google", google);
        m.put("github", github);
        return m;
    }
}
