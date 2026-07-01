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
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
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
        // JWKS may be fetched from an internal cluster URL (auth-lib.jwk-set-uri)
        // to avoid hairpinning key fetches out to the public issuer (e.g. through
        // Cloudflare); when unset we derive the public certs URL for back-compat.
        // Either way the `iss` claim is still validated against the PUBLIC
        // issuer-uri below.
        String jwkSetUri = (props.jwkSetUri() != null && !props.jwkSetUri().isBlank())
            ? props.jwkSetUri()
            : props.issuerUri() + "/protocol/openid-connect/certs";

        // Explicit connect+read timeout on the JWKS fetch so a slow/hairpinned
        // JWKS endpoint fails fast instead of hanging the request thread.
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(props.httpTimeout());
        requestFactory.setReadTimeout(props.httpTimeout());
        RestTemplate jwkRestTemplate = new RestTemplate(requestFactory);

        NimbusJwtDecoder decoder = NimbusJwtDecoder
            .withJwkSetUri(jwkSetUri)
            .restOperations(jwkRestTemplate)
            .build();

        // Validate iss == public issuer-uri PLUS the default timestamp validators.
        // (withJwkSetUri(...).build() only checks signature+exp otherwise.)
        // Nimbus caches the fetched JWK set by default; auth-lib.jwks-cache-ttl is
        // exposed for future wiring should an explicit TTL knob be needed.
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(props.issuerUri()));
        return decoder;
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
