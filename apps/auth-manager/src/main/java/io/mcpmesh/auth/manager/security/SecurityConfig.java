package io.mcpmesh.auth.manager.security;

import io.mcpmesh.auth.manager.keycloak.KeycloakProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Multi-realm resource-server config. JWTs from any tenant realm under
 * {@code keycloak.url}/realms/* are validated against that realm's JWKS;
 * unknown issuers are rejected.
 *
 * <p>Behavior for unauthenticated requests is still permitAll — gating
 * lands in a follow-up commit. This commit only puts the validation
 * plumbing in place so any JWT that IS sent populates the security
 * context (so audit/principal resolution can begin working).
 *
 * <p>NOT replacing auth-lib v2 here. auth-lib v2 is single-realm (a
 * consumer app validates one realm's tokens). auth-manager is the
 * platform's control plane and accepts JWTs from every tenant realm.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    private final KeycloakProperties keycloak;
    private final ConcurrentMap<String, AuthenticationManager> managers = new ConcurrentHashMap<>();

    public SecurityConfig(KeycloakProperties keycloak) {
        this.keycloak = keycloak;
    }

    @Bean
    public JwtIssuerAuthenticationManagerResolver authenticationManagerResolver() {
        String trustedPrefix = keycloak.url() + (keycloak.url().endsWith("/") ? "" : "/") + "realms/";
        return new JwtIssuerAuthenticationManagerResolver((String issuer) -> {
            if (issuer == null || !issuer.startsWith(trustedPrefix)) {
                log.warn("Rejecting JWT with unknown issuer: {}", issuer);
                return null;
            }
            return managers.computeIfAbsent(issuer, iss -> {
                log.info("Building JwtDecoder for issuer: {}", iss);
                JwtDecoder decoder = NimbusJwtDecoder
                    .withJwkSetUri(iss + "/protocol/openid-connect/certs")
                    .build();
                JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);
                return provider::authenticate;
            });
        });
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
        HttpSecurity http,
        JwtIssuerAuthenticationManagerResolver resolver
    ) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(resolver));
        return http.build();
    }
}
