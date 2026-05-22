package io.mcpmesh.auth.lib.security;

import io.mcpmesh.auth.lib.AuthLibProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

/**
 * Default security wiring for consumer apps using auth-lib v2.
 *
 * <p>Bootstraps a resource-server SecurityFilterChain that:
 * <ul>
 *   <li>Validates JWT signatures via Keycloak's JWKS (Nimbus default JWK source caching)</li>
 *   <li>Extracts authorities from JWT scopes AND from Keycloak's UMA permission endpoint
 *       (via {@link PermissionJwtAuthenticationConverter})</li>
 *   <li>Disables CSRF (resource servers are stateless)</li>
 *   <li>Sets session policy to STATELESS</li>
 *   <li>Permits {@code /actuator/health/**} unauthenticated; everything else requires JWT</li>
 * </ul>
 *
 * <p>Consumers needing custom path patterns can override the
 * {@code SecurityFilterChain} bean (Spring's standard override path).
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public JwtDecoder jwtDecoder(AuthLibProperties props) {
        return NimbusJwtDecoder
            .withJwkSetUri(props.issuerUri() + "/protocol/openid-connect/certs")
            .build();
    }

    @Bean
    public RestTemplate authLibRestTemplate() {
        return new RestTemplate();
    }

    @Bean
    public PermissionService permissionService(
        AuthLibProperties props,
        RestTemplate authLibRestTemplate,
        org.springframework.beans.factory.ObjectProvider<org.springframework.data.redis.core.StringRedisTemplate> redis
    ) {
        return new PermissionService(props, authLibRestTemplate, redis.getIfAvailable());
    }

    @Bean
    public io.mcpmesh.auth.lib.Permissions permissions(
        AuthLibProperties props,
        RestTemplate authLibRestTemplate,
        org.springframework.beans.factory.ObjectProvider<org.springframework.data.redis.core.StringRedisTemplate> redis
    ) {
        return new io.mcpmesh.auth.lib.Permissions(props, authLibRestTemplate, redis.getIfAvailable());
    }

    @Bean
    public PermissionJwtAuthenticationConverter jwtAuthenticationConverter(PermissionService permissions) {
        return new PermissionJwtAuthenticationConverter(permissions);
    }

    @Bean
    public SecurityFilterChain authLibSecurityFilterChain(
        HttpSecurity http,
        PermissionJwtAuthenticationConverter converter
    ) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health/**").permitAll()
                .anyRequest().authenticated())
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(converter)));
        return http.build();
    }
}
