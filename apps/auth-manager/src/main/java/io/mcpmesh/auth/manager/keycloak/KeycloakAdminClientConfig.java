package io.mcpmesh.auth.manager.keycloak;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Builds the single {@link Keycloak} admin-client bean used by
 * {@link KeycloakAdminService} and any future provisioning code.
 *
 * <p>The admin client maintains its own token lifecycle internally;
 * we do not manage refresh.
 */
@Configuration
@EnableConfigurationProperties({KeycloakProperties.class, PlatformOAuthProperties.class})
public class KeycloakAdminClientConfig {

    @Bean
    public Keycloak keycloakAdminClient(KeycloakProperties props) {
        return KeycloakBuilder.builder()
            .serverUrl(props.url())
            .realm(props.realm())
            .grantType(OAuth2Constants.PASSWORD)
            .clientId(props.admin().clientId())
            .username(props.admin().username())
            .password(props.admin().password())
            .build();
    }
}
