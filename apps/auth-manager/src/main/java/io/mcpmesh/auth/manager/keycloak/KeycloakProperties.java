package io.mcpmesh.auth.manager.keycloak;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Connection settings for the Keycloak Admin Client.
 * Bound from properties under `keycloak.*` (see application.yaml).
 */
@ConfigurationProperties("keycloak")
public record KeycloakProperties(

    @URL @NotBlank String url,
    @NotBlank String realm,
    @Valid @NotNull Admin admin,
    Duration connectTimeout,
    Duration readTimeout
) {
    public KeycloakProperties {
        if (connectTimeout == null) connectTimeout = Duration.ofSeconds(5);
        if (readTimeout    == null) readTimeout    = Duration.ofSeconds(10);
    }

    /** Credentials used by the admin client to obtain tokens against {@code keycloak.realm}. */
    public record Admin(
        @NotBlank String clientId,
        @NotBlank String username,
        @NotBlank String password
    ) {}
}
