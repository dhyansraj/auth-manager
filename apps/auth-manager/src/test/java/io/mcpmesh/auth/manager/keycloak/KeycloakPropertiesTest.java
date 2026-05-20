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
            Duration.ofSeconds(1), Duration.ofSeconds(2)
        );
        assertThat(props.connectTimeout()).isEqualTo(Duration.ofSeconds(1));
        assertThat(props.readTimeout()).isEqualTo(Duration.ofSeconds(2));
    }
}
