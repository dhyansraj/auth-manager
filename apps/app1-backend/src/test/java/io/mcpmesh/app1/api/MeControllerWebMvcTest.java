package io.mcpmesh.app1.api;

import io.mcpmesh.auth.lib.Permissions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MVC-layer test for {@link MeController}. Mirrors auth-manager's
 * {@code TenantControllerWebMvcTest} pattern: strips down the boot context
 * (no Redis, no oauth2 resource-server autoconfig) and supplies an
 * authentication-only test filter chain so {@code jwt()} request post
 * processors can inject test JWTs without a real decoder.
 */
@SpringBootTest(
    classes = MeControllerWebMvcTest.TestApp.class,
    webEnvironment = SpringBootTest.WebEnvironment.MOCK,
    properties = {
        "app1.tenant.id=00000000-0000-0000-0000-000000000001",
        "app1.tenant.slug=app1",
        "app1.tenant.display-name=App One",
        "app1.tenant.realm-name=t-app1",
        "spring.autoconfigure.exclude=" +
            "io.mcpmesh.auth.lib.AuthLibAutoConfiguration," +
            "org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration," +
            "org.springframework.boot.data.redis.autoconfigure.DataRedisRepositoriesAutoConfiguration," +
            "org.springframework.boot.security.oauth2.server.resource.autoconfigure.servlet.OAuth2ResourceServerAutoConfiguration," +
            "org.springframework.boot.security.oauth2.server.resource.autoconfigure.reactive.ReactiveOAuth2ResourceServerAutoConfiguration"
    }
)
class MeControllerWebMvcTest {

    @MockitoBean Permissions permissions;

    @Autowired WebApplicationContext context;
    @Autowired FilterChainProxy springSecurityFilterChain;

    MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context)
            .addFilters(springSecurityFilterChain)
            .build();
    }

    @Test
    void me_returns_401_without_auth() throws Exception {
        mvc.perform(get("/api/me"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void me_returns_tenant_context_with_permissions() throws Exception {
        when(permissions.allFor(any())).thenReturn(Set.of(
            "ORDER_VIEW", "ORDER_APPROVE", "INVOICE_VIEW"));

        mvc.perform(get("/api/me").with(jwt().jwt(j -> j
                .subject("alice-sub")
                .claim("email", "alice@app1.test")
                .claim("preferred_username", "alice@app1.test")
                .claim("name", "Alice Tester"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.context").value("tenant"))
            .andExpect(jsonPath("$.user.id").value("alice-sub"))
            .andExpect(jsonPath("$.user.email").value("alice@app1.test"))
            .andExpect(jsonPath("$.user.preferredUsername").value("alice@app1.test"))
            .andExpect(jsonPath("$.user.name").value("Alice Tester"))
            .andExpect(jsonPath("$.tenant.slug").value("app1"))
            .andExpect(jsonPath("$.tenant.displayName").value("App One"))
            .andExpect(jsonPath("$.tenant.realmName").value("t-app1"))
            .andExpect(jsonPath("$.isPlatformAdmin").value(false))
            .andExpect(jsonPath("$.isTenantAdmin").value(false))
            .andExpect(jsonPath("$.permissions.length()").value(3));
    }

    @Test
    void me_flags_tenant_admin_when_usermanagement_role_present() throws Exception {
        when(permissions.allFor(any())).thenReturn(Set.of("ORDER_VIEW"));

        mvc.perform(get("/api/me").with(jwt().jwt(j -> j
                .subject("alice-sub")
                .claim("email", "alice@app1.test")
                .claim("preferred_username", "alice@app1.test")
                .claim("resource_access", Map.of(
                    "usermanagement", Map.of("roles", List.of("tenant-admin"))
                )))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.isTenantAdmin").value(true))
            .andExpect(jsonPath("$.isPlatformAdmin").value(false));
    }

    @Test
    void me_returns_empty_permissions_when_uma_unavailable() throws Exception {
        when(permissions.allFor(any())).thenReturn(Set.of());

        mvc.perform(get("/api/me").with(jwt().jwt(j -> j
                .subject("bob-sub")
                .claim("email", "bob@app1.test")
                .claim("preferred_username", "bob@app1.test"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.permissions.length()").value(0))
            .andExpect(jsonPath("$.isTenantAdmin").value(false));
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @ComponentScan(
        basePackages = "io.mcpmesh.app1.api",
        useDefaultFilters = false,
        includeFilters = @ComponentScan.Filter(
            type = FilterType.ASSIGNABLE_TYPE,
            classes = {MeController.class}
        )
    )
    @Import(TestSecurityConfig.class)
    static class TestApp {
    }

    @Configuration
    @EnableMethodSecurity
    static class TestSecurityConfig {

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
