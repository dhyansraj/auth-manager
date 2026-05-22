package io.mcpmesh.auth.manager.idp;

import io.mcpmesh.auth.manager.api.GlobalExceptionHandler;
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
import org.springframework.http.HttpStatus;
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
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(
    classes = IdentityProvidersControllerWebMvcTest.TestApp.class,
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
class IdentityProvidersControllerWebMvcTest {

    @MockitoBean IdentityProvidersService service;
    @MockitoBean(name = "tenantSecurity") TenantSecurity tenantSecurity;

    @Autowired WebApplicationContext context;
    @Autowired FilterChainProxy springSecurityFilterChain;

    MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context)
            .addFilters(springSecurityFilterChain)
            .build();
    }

    // ---- auth gating ----

    @Test
    void list_returns_401_withoutAuth() throws Exception {
        mvc.perform(get("/api/v1/tenants/app1/identity-providers"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void update_returns_401_withoutAuth() throws Exception {
        mvc.perform(put("/api/v1/tenants/app1/identity-providers/google")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"enabled\":true}"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void list_returns_403_whenCantSeeTenant() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(anyString())).thenReturn(false);
        mvc.perform(get("/api/v1/tenants/app1/identity-providers").with(jwt()))
            .andExpect(status().isForbidden());
    }

    @Test
    void update_returns_403_whenCantManageTenant() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq("app1"))).thenReturn(true);
        when(tenantSecurity.canManageTenant(eq("app1"))).thenReturn(false);
        mvc.perform(put("/api/v1/tenants/app1/identity-providers/google")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"enabled\":true}"))
            .andExpect(status().isForbidden());
    }

    // ---- happy paths ----

    @Test
    void list_returns_200_andProviderList() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq("app1"))).thenReturn(true);
        when(service.list(eq("app1"))).thenReturn(List.of(
            new IdentityProviderDto("google", "Google", false, false),
            new IdentityProviderDto("github", "GitHub", false, false)
        ));

        mvc.perform(get("/api/v1/tenants/app1/identity-providers").with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$[0].id").value("google"))
            .andExpect(jsonPath("$[0].displayName").value("Google"))
            .andExpect(jsonPath("$[0].enabled").value(false))
            .andExpect(jsonPath("$[0].available").value(false))
            .andExpect(jsonPath("$[1].id").value("github"));
    }

    @Test
    void update_returns_200_onEnable_whenAvailable() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq("app1"))).thenReturn(true);
        when(tenantSecurity.canManageTenant(eq("app1"))).thenReturn(true);
        when(service.setEnabled(eq("app1"), eq("google"), eq(true), anyString()))
            .thenReturn(new IdentityProviderDto("google", "Google", true, true));

        mvc.perform(put("/api/v1/tenants/app1/identity-providers/google")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"enabled\":true}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.enabled").value(true))
            .andExpect(jsonPath("$.available").value(true));
    }

    @Test
    void update_returns_422_whenEnablingUnavailableProvider() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq("app1"))).thenReturn(true);
        when(tenantSecurity.canManageTenant(eq("app1"))).thenReturn(true);
        doThrow(new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "creds missing"))
            .when(service).setEnabled(eq("app1"), eq("google"), eq(true), anyString());

        mvc.perform(put("/api/v1/tenants/app1/identity-providers/google")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"enabled\":true}"))
            .andExpect(status().isUnprocessableEntity());
    }

    @Test
    void update_returns_400_forUnsupportedProvider() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq("app1"))).thenReturn(true);
        when(tenantSecurity.canManageTenant(eq("app1"))).thenReturn(true);
        doThrow(new IllegalArgumentException("Unsupported provider: facebook"))
            .when(service).setEnabled(eq("app1"), eq("facebook"), eq(true), anyString());

        mvc.perform(put("/api/v1/tenants/app1/identity-providers/facebook")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"enabled\":true}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void update_returns_400_whenBodyMissingEnabledField() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq("app1"))).thenReturn(true);
        when(tenantSecurity.canManageTenant(eq("app1"))).thenReturn(true);
        mvc.perform(put("/api/v1/tenants/app1/identity-providers/google")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            .andExpect(status().isBadRequest());
    }

    // ---- test app ----

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @ComponentScan(
        basePackages = {
            "io.mcpmesh.auth.manager.idp",
            "io.mcpmesh.auth.manager.api"
        },
        useDefaultFilters = false,
        includeFilters = @ComponentScan.Filter(
            type = FilterType.ASSIGNABLE_TYPE,
            classes = {IdentityProvidersController.class, GlobalExceptionHandler.class}
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
