package io.mcpmesh.auth.manager.roles;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mcpmesh.auth.manager.api.GlobalExceptionHandler;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.security.TenantSecurity;
import io.mcpmesh.auth.manager.service.TenantService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.UserRepresentation;
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
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MVC-layer test for {@link UserRolesController}: slug-based user view with
 * realmRoles, plus atomic replace of composite roles.
 */
@SpringBootTest(
    classes = UserRolesControllerWebMvcTest.TestApp.class,
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
class UserRolesControllerWebMvcTest {

    private static final String SLUG = "app1";
    private static final String REALM = "t-app1";
    private static final String USER_ID = "user-1";

    @MockitoBean RolesService rolesService;
    @MockitoBean TenantService tenantService;
    @MockitoBean KeycloakAdminService keycloak;
    @MockitoBean(name = "tenantSecurity") TenantSecurity tenantSecurity;

    @Autowired WebApplicationContext context;
    @Autowired FilterChainProxy springSecurityFilterChain;

    MockMvc mvc;
    final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context)
            .addFilters(springSecurityFilterChain)
            .build();

        Tenant t = mock(Tenant.class);
        when(t.getRealmName()).thenReturn(REALM);
        when(t.getId()).thenReturn(UUID.randomUUID());
        when(tenantService.getBySlug(SLUG)).thenReturn(t);

        UserRepresentation u = new UserRepresentation();
        u.setId(USER_ID);
        u.setUsername("alice");
        u.setEmail("alice@app1.test");
        u.setFirstName("Alice");
        u.setLastName("Doe");
        u.setEnabled(true);
        u.setEmailVerified(true);
        when(keycloak.getUser(REALM, USER_ID)).thenReturn(u);
        when(keycloak.getUserClientRoles(REALM, USER_ID, "usermanagement"))
            .thenReturn(List.of("tenant-admin"));
    }

    // ---- auth gating ----

    @Test
    void get_returns_401_withoutAuth() throws Exception {
        mvc.perform(get("/api/v1/tenants/app1/users/" + USER_ID))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void put_returns_401_withoutAuth() throws Exception {
        mvc.perform(put("/api/v1/tenants/app1/users/" + USER_ID + "/roles")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roleNames\":[]}"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void get_returns_403_whenCantSeeTenant() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(anyString())).thenReturn(false);
        mvc.perform(get("/api/v1/tenants/app1/users/" + USER_ID).with(jwt()))
            .andExpect(status().isForbidden());
    }

    @Test
    void put_returns_403_whenCantManageTenant() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(anyString())).thenReturn(true);
        when(tenantSecurity.canManageTenant(anyString())).thenReturn(false);
        mvc.perform(put("/api/v1/tenants/app1/users/" + USER_ID + "/roles")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roleNames\":[]}"))
            .andExpect(status().isForbidden());
    }

    // ---- happy paths ----

    @Test
    void get_returns_200_withRealmRoles() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq(SLUG))).thenReturn(true);
        when(rolesService.userManageableRealmRoles(eq(SLUG), eq(USER_ID)))
            .thenReturn(List.of("Order Manager", "Viewer"));

        mvc.perform(get("/api/v1/tenants/app1/users/" + USER_ID).with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(USER_ID))
            .andExpect(jsonPath("$.username").value("alice"))
            .andExpect(jsonPath("$.roles[0]").value("tenant-admin"))
            .andExpect(jsonPath("$.realmRoles[0]").value("Order Manager"))
            .andExpect(jsonPath("$.realmRoles[1]").value("Viewer"));
    }

    @Test
    void put_returns_200_andAtomicReplace() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq(SLUG))).thenReturn(true);
        when(tenantSecurity.canManageTenant(eq(SLUG))).thenReturn(true);
        when(rolesService.updateUserRoles(eq(SLUG), eq(USER_ID), eq(List.of("Order Manager")), anyString()))
            .thenReturn(new RolesService.AssignResult(List.of("Order Manager"), List.of("Viewer")));
        when(rolesService.userManageableRealmRoles(eq(SLUG), eq(USER_ID)))
            .thenReturn(List.of("Order Manager"));

        mvc.perform(put("/api/v1/tenants/app1/users/" + USER_ID + "/roles")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roleNames\":[\"Order Manager\"]}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.realmRoles[0]").value("Order Manager"))
            .andExpect(jsonPath("$.realmRoles[1]").doesNotExist());
    }

    @Test
    void put_returns_400_whenUnknownRole() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq(SLUG))).thenReturn(true);
        when(tenantSecurity.canManageTenant(eq(SLUG))).thenReturn(true);
        doThrow(new IllegalArgumentException("Unknown or system role(s): Ghost"))
            .when(rolesService).updateUserRoles(eq(SLUG), eq(USER_ID), any(), anyString());

        mvc.perform(put("/api/v1/tenants/app1/users/" + USER_ID + "/roles")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roleNames\":[\"Ghost\"]}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void put_returns_400_whenSystemRoleAttempted() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq(SLUG))).thenReturn(true);
        when(tenantSecurity.canManageTenant(eq(SLUG))).thenReturn(true);
        doThrow(new IllegalArgumentException("Unknown or system role(s): tenant-admin"))
            .when(rolesService).updateUserRoles(eq(SLUG), eq(USER_ID), any(), anyString());

        mvc.perform(put("/api/v1/tenants/app1/users/" + USER_ID + "/roles")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roleNames\":[\"tenant-admin\"]}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void put_returns_400_whenRoleNamesMissing() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq(SLUG))).thenReturn(true);
        when(tenantSecurity.canManageTenant(eq(SLUG))).thenReturn(true);

        mvc.perform(put("/api/v1/tenants/app1/users/" + USER_ID + "/roles")
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
            "io.mcpmesh.auth.manager.roles",
            "io.mcpmesh.auth.manager.api"
        },
        useDefaultFilters = false,
        includeFilters = @ComponentScan.Filter(
            type = FilterType.ASSIGNABLE_TYPE,
            classes = {UserRolesController.class, GlobalExceptionHandler.class}
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
