package io.mcpmesh.auth.manager.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mcpmesh.auth.manager.routing.RoutingConfigService;
import io.mcpmesh.auth.manager.routing.model.AuthMode;
import io.mcpmesh.auth.manager.routing.model.RoutingConfig;
import io.mcpmesh.auth.manager.routing.model.RoutingRule;
import io.mcpmesh.auth.manager.security.Permissions;
import io.mcpmesh.auth.manager.security.TenantSecurity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MVC-layer test for {@link RouteController}. Uses a stripped-down boot
 * context (no JPA / no Keycloak / no Postgres / no Redis) so it stays
 * in surefire (i.e. fast). The production
 * {@link io.mcpmesh.auth.manager.security.SecurityConfig} is replaced
 * with {@link TestSecurityConfig} which requires authentication on every
 * request and accepts the test-minted JWTs from
 * {@code SecurityMockMvcRequestPostProcessors.jwt()}.
 */
@SpringBootTest(
    classes = RouteControllerWebMvcTest.TestApp.class,
    webEnvironment = SpringBootTest.WebEnvironment.MOCK,
    properties = {
        "spring.autoconfigure.exclude=" +
            "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration," +
            "org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration," +
            "org.springframework.boot.data.jpa.autoconfigure.DataJpaRepositoriesAutoConfiguration," +
            "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration," +
            "org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration," +
            "org.springframework.boot.data.redis.autoconfigure.DataRedisRepositoriesAutoConfiguration," +
            "org.springframework.boot.security.oauth2.server.resource.autoconfigure.servlet.OAuth2ResourceServerAutoConfiguration," +
            "org.springframework.boot.security.oauth2.server.resource.autoconfigure.reactive.ReactiveOAuth2ResourceServerAutoConfiguration"
    }
)
class RouteControllerWebMvcTest {

    @MockitoBean RoutingConfigService routingService;
    @MockitoBean(name = "tenantSecurity") TenantSecurity tenantSecurity;
    @MockitoBean(name = "perms") Permissions perms;

    @Autowired WebApplicationContext context;
    @Autowired FilterChainProxy springSecurityFilterChain;

    MockMvc mvc;
    final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context)
            .addFilters(springSecurityFilterChain)
            .build();
    }

    @Test
    void get_returns_401_without_auth() throws Exception {
        mvc.perform(get("/api/v1/tenants/acme/routes"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void put_returns_401_without_auth() throws Exception {
        mvc.perform(put("/api/v1/tenants/acme/routes")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(sampleConfig())))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void get_returns_403_for_non_admin() throws Exception {
        when(perms.hasOnTenant(anyString(), eq("TENANT_VIEW"))).thenReturn(false);
        mvc.perform(get("/api/v1/tenants/acme/routes").with(jwt()))
            .andExpect(status().isForbidden());
    }

    @Test
    void put_returns_403_for_non_admin() throws Exception {
        when(perms.hasOnTenant(anyString(), eq("ROUTES_EDIT"))).thenReturn(false);
        mvc.perform(put("/api/v1/tenants/acme/routes")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(sampleConfig())))
            .andExpect(status().isForbidden());
    }

    @Test
    void get_returns_200_for_admin() throws Exception {
        when(perms.hasOnTenant(eq("acme"), eq("TENANT_VIEW"))).thenReturn(true);
        when(routingService.getForTenant("acme")).thenReturn(sampleConfig());

        mvc.perform(get("/api/v1/tenants/acme/routes").with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.rules[0].path").value("/api/*"))
            .andExpect(jsonPath("$.rules[1].path").value("/*"))
            .andExpect(jsonPath("$.targets.backend").value("be:8080"));
    }

    @Test
    void put_returns_200_for_admin_happy_path() throws Exception {
        when(perms.hasOnTenant(eq("acme"), eq("ROUTES_EDIT"))).thenReturn(true);
        when(routingService.replaceForTenant(eq("acme"), any(RoutingConfig.class)))
            .thenAnswer(inv -> inv.getArgument(1));

        mvc.perform(put("/api/v1/tenants/acme/routes")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(sampleConfig())))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.rules[1].path").value("/*"));
    }

    @Test
    void put_returns_400_for_missing_catch_all() throws Exception {
        when(perms.hasOnTenant(eq("acme"), eq("ROUTES_EDIT"))).thenReturn(true);

        // Hand-rolled JSON to bypass the record's constructor-side validation
        // and exercise the HTTP-boundary error path.
        String body = """
            {
              "rules": [
                {"path": "/api/*", "authMode": "REQUIRED", "target": "backend"}
              ],
              "targets": {"backend": "be:8080"}
            }
            """;
        mvc.perform(put("/api/v1/tenants/acme/routes")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isBadRequest());
    }

    @Test
    void put_returns_400_for_empty_rules() throws Exception {
        when(perms.hasOnTenant(eq("acme"), eq("ROUTES_EDIT"))).thenReturn(true);

        String body = """
            {
              "rules": [],
              "targets": {}
            }
            """;
        mvc.perform(put("/api/v1/tenants/acme/routes")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isBadRequest());
    }

    private static RoutingConfig sampleConfig() {
        return new RoutingConfig(
            List.of(
                new RoutingRule("/api/*", AuthMode.REQUIRED, "backend"),
                new RoutingRule("/*",     AuthMode.OPTIONAL, "frontend")
            ),
            Map.of(
                "backend",  "be:8080",
                "frontend", "fe:80"
            )
        );
    }

    /**
     * Minimal Spring Boot application context for the test. Component-scans
     * only the controller + global exception handler (no service / persistence
     * / security beans pulled in transitively). The security layer is
     * supplied locally by {@link TestSecurityConfig}.
     */
    @SpringBootConfiguration
    @EnableAutoConfiguration
    @ComponentScan(
        basePackages = "io.mcpmesh.auth.manager.api",
        useDefaultFilters = false,
        includeFilters = @ComponentScan.Filter(
            type = FilterType.ASSIGNABLE_TYPE,
            classes = {RouteController.class, GlobalExceptionHandler.class}
        )
    )
    @Import(TestSecurityConfig.class)
    static class TestApp {
    }

    @Configuration
    @EnableMethodSecurity
    static class TestSecurityConfig {

        /**
         * Slice security: require auth and return 401 on missing auth via a
         * plain {@link org.springframework.security.web.authentication.HttpStatusEntryPoint}.
         * The {@code jwt()} request-post-processor in the tests injects a
         * {@link org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken}
         * directly into the security context, so it satisfies
         * {@code anyRequest().authenticated()} without going through any
         * OAuth2 decoder. This keeps the slice free of JwtDecoder / JWKS
         * setup.
         */
        @Bean
        SecurityFilterChain filter(HttpSecurity http) throws Exception {
            http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(a -> a.anyRequest().authenticated())
                .exceptionHandling(e -> e.authenticationEntryPoint(
                    new org.springframework.security.web.authentication.HttpStatusEntryPoint(
                        org.springframework.http.HttpStatus.UNAUTHORIZED)));
            return http.build();
        }
    }
}
