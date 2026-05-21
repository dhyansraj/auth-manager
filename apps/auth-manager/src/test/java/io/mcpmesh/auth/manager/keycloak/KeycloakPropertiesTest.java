package io.mcpmesh.auth.manager.keycloak;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakPropertiesTest {

    @Test
    void appliesDefaultTimeoutsWhenNotProvided() {
        var props = new KeycloakProperties(
            "http://localhost:8180", "master",
            new KeycloakProperties.Admin("admin-cli", "admin", "admin"),
            null,
            null, null
        );
        assertThat(props.connectTimeout()).isEqualTo(Duration.ofSeconds(5));
        assertThat(props.readTimeout()).isEqualTo(Duration.ofSeconds(10));
    }

    @Test
    void preservesProvidedTimeouts() {
        var props = new KeycloakProperties(
            "http://localhost:8180", "master",
            new KeycloakProperties.Admin("admin-cli", "admin", "admin"),
            null,
            Duration.ofSeconds(1), Duration.ofSeconds(2)
        );
        assertThat(props.connectTimeout()).isEqualTo(Duration.ofSeconds(1));
        assertThat(props.readTimeout()).isEqualTo(Duration.ofSeconds(2));
    }

    @Test
    void appliesDefaultPlatformWhenNotProvided() {
        var props = new KeycloakProperties(
            "http://localhost:8180", "master",
            new KeycloakProperties.Admin("admin-cli", "admin", "admin"),
            null,
            null, null
        );
        assertThat(props.platform()).isNotNull();
        assertThat(props.platform().realm()).isEqualTo("dev");
        assertThat(props.platform().role()).isEqualTo("platform-admin");
    }

    @Test
    void preservesProvidedPlatform() {
        var props = new KeycloakProperties(
            "http://localhost:8180", "master",
            new KeycloakProperties.Admin("admin-cli", "admin", "admin"),
            new KeycloakProperties.Platform("admin-realm", "super-admin"),
            null, null
        );
        assertThat(props.platform().realm()).isEqualTo("admin-realm");
        assertThat(props.platform().role()).isEqualTo("super-admin");
    }
}
