package io.mcpmesh.auth.lib.security;

import io.mcpmesh.auth.lib.AuthLibProperties;
import io.mcpmesh.auth.lib.PermissionsCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
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

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

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
        PermissionsCache permissionsCache
    ) {
        return new PermissionService(props, authLibRestTemplate, permissionsCache);
    }

    @Bean
    public io.mcpmesh.auth.lib.Permissions permissions(
        AuthLibProperties props,
        RestTemplate authLibRestTemplate,
        PermissionsCache permissionsCache
    ) {
        return new io.mcpmesh.auth.lib.Permissions(props, authLibRestTemplate, permissionsCache);
    }

    @Bean
    public PermissionJwtAuthenticationConverter jwtAuthenticationConverter(PermissionService permissions) {
        return new PermissionJwtAuthenticationConverter(permissions);
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain authLibSecurityFilterChain(
        HttpSecurity http,
        PermissionJwtAuthenticationConverter converter,
        @Value("${auth-lib.dev-mode:false}") boolean devMode
    ) throws Exception {
        if (devMode) {
            log.warn("auth-lib dev-mode ENABLED: all requests permitted, JWT validation DISABLED — never use in production");
            http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
            return http.build();
        }
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
