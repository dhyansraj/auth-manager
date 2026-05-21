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
    @Valid Platform platform,
    Duration connectTimeout,
    Duration readTimeout
) {
    public KeycloakProperties {
        if (connectTimeout == null) connectTimeout = Duration.ofSeconds(5);
        if (readTimeout    == null) readTimeout    = Duration.ofSeconds(10);
        if (platform       == null) platform       = new Platform("dev", "platform-admin");
    }

    /** Credentials used by the admin client to obtain tokens against {@code keycloak.realm}. */
    public record Admin(
        @NotBlank String clientId,
        @NotBlank String username,
        @NotBlank String password
    ) {}

    /**
     * Cross-tenant platform-admin realm. A user signed into this realm with
     * the {@link #role()} realm role bypasses per-tenant authorization checks.
     */
    public record Platform(
        @NotBlank String realm,
        @NotBlank String role
    ) {
        public Platform {
            if (realm == null || realm.isBlank()) realm = "dev";
            if (role  == null || role.isBlank())  role  = "platform-admin";
        }
    }
}
