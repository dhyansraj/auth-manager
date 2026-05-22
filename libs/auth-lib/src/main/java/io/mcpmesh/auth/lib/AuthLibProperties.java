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
 *   <li>{@code auth-lib.issuer-uri}: e.g. {@code https://kc.example.com/realms/tenant1}</li>
 *   <li>{@code auth-lib.client-id}: this app's OIDC client_id in that realm</li>
 *   <li>{@code auth-lib.client-secret}: confidential client secret</li>
 *   <li>{@code auth-lib.audiences}: optional list of additional resource-server
 *       clientIds the {@code Permissions} helper should aggregate UMA permissions
 *       across (e.g. {@code [orders, invoices]}). When empty/null, defaults to a
 *       single-element list containing {@link #clientId()}.</li>
 * </ul>
 */
@ConfigurationProperties("auth-lib")
public record AuthLibProperties(
    @URL @NotBlank String issuerUri,
    @NotBlank String clientId,
    @NotBlank String clientSecret,
    List<String> audiences,
    Cache cache
) {
    public AuthLibProperties {
        if (cache == null) cache = new Cache(true, Duration.ofMinutes(5));
        if (audiences == null || audiences.isEmpty()) {
            audiences = List.of(clientId);
        }
    }

    /** Permission cache settings. */
    public record Cache(
        boolean enabled,
        Duration ttl
    ) {}
}
