package io.mcpmesh.auth.lib;

import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

/**
 * Configures auth-lib's connection to a Keycloak realm.
 *
 * <p>Bound under {@code auth-lib.*}. Required properties:
 * <ul>
 *   <li>{@code auth-lib.issuer-uri}: e.g. {@code https://kc.example.com/realms/tenant1}.
 *       Always the PUBLIC issuer — must match the JWT {@code iss} claim exactly,
 *       since iss is validated against it.</li>
 *   <li>{@code auth-lib.client-id}: this app's OIDC client_id in that realm</li>
 *   <li>{@code auth-lib.client-secret}: confidential client secret</li>
 *   <li>{@code auth-lib.audiences}: optional list of additional resource-server
 *       clientIds the {@code Permissions} helper should aggregate UMA permissions
 *       across (e.g. {@code [orders, invoices]}). When empty/null, defaults to a
 *       single-element list containing {@link #clientId()}.</li>
 * </ul>
 *
 * <p>Optional properties:
 * <ul>
 *   <li>{@code auth-lib.jwk-set-uri}: explicit JWKS endpoint. When set, signing
 *       keys are fetched from it instead of the derived
 *       {@code issuer-uri + "/protocol/openid-connect/certs"}. In-cluster
 *       backends should point this at the internal Keycloak certs URL to avoid
 *       hairpinning JWKS fetches out to the public issuer (e.g. through
 *       Cloudflare). The {@code iss} claim is still validated against the public
 *       {@code issuer-uri}. When null/blank, the public certs URL is derived
 *       (back-compat).</li>
 *   <li>{@code auth-lib.http-timeout}: connect+read timeout for the JWKS fetch.
 *       Default {@code 5s} (parity with the Python lib's
 *       {@code AUTH_LIB_HTTP_TIMEOUT_SECONDS=5}).</li>
 *   <li>{@code auth-lib.jwks-cache-ttl}: how long fetched JWKS are cached.
 *       Default {@code 1h} (parity with the Python lib's
 *       {@code AUTH_LIB_JWKS_CACHE_TTL_SECONDS=3600}).</li>
 * </ul>
 */
@ConfigurationProperties("auth-lib")
public record AuthLibProperties(
    @URL @NotBlank String issuerUri,
    @NotBlank String clientId,
    @NotBlank String clientSecret,
    List<String> audiences,
    Cache cache,
    String jwkSetUri,
    Duration httpTimeout,
    Duration jwksCacheTtl
) {
    public AuthLibProperties {
        if (cache == null) cache = new Cache(true, Duration.ofMinutes(5));
        if (audiences == null || audiences.isEmpty()) {
            audiences = List.of(clientId);
        }
        if (httpTimeout == null) httpTimeout = Duration.ofSeconds(5);
        if (jwksCacheTtl == null) jwksCacheTtl = Duration.ofHours(1);
    }

    /**
     * Permission cache settings.
     *
     * <p>Behavior matrix:
     * <ul>
     *   <li>{@code enabled=true} + {@code spring-boot-starter-data-redis} on
     *       the classpath: cache hits Redis (via {@code RedisPermissionsCache},
     *       autoconfigured by {@code RedisPermissionsCacheAutoConfiguration}).</li>
     *   <li>{@code enabled=true} + no Redis starter: cache uses an in-process map
     *       (per-replica, lazy TTL eviction — {@code InMemoryPermissionsCache}).
     *       This is the default for tenants who do not add the Redis starter to
     *       their own pom.</li>
     *   <li>{@code enabled=false}: cache is bypassed entirely; every permission
     *       lookup hits Keycloak's UMA endpoint.</li>
     * </ul>
     */
    public record Cache(
        boolean enabled,
        Duration ttl
    ) {}
}
