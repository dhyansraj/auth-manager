package io.mcpmesh.auth.lib;

import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Configures auth-lib's connection to a Keycloak realm.
 *
 * <p>Bound under {@code auth-lib.*}. Required properties:
 * <ul>
 *   <li>{@code auth-lib.issuer-uri}: e.g. {@code https://kc.example.com/realms/tenant1}</li>
 *   <li>{@code auth-lib.client-id}: this app's OIDC client_id in that realm</li>
 *   <li>{@code auth-lib.client-secret}: confidential client secret</li>
 * </ul>
 */
@ConfigurationProperties("auth-lib")
public record AuthLibProperties(
    @URL @NotBlank String issuerUri,
    @NotBlank String clientId,
    @NotBlank String clientSecret,
    Cache cache
) {
    public AuthLibProperties {
        if (cache == null) cache = new Cache(true, Duration.ofMinutes(5));
    }

    /** Permission cache settings. */
    public record Cache(
        boolean enabled,
        Duration ttl
    ) {}
}
