package io.mcpmesh.auth.manager.roles;

import com.fasterxml.jackson.databind.ObjectMapper;
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MVC-layer test for {@link RolesController}. Uses a stripped-down boot
 * context (no JPA / no Keycloak / no Postgres / no Redis) so it stays fast.
 */
@SpringBootTest(
    classes = RolesControllerWebMvcTest.TestApp.class,
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
class RolesControllerWebMvcTest {

    @MockitoBean RolesService rolesService;
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
    }

    // ---- auth gating ----

    @Test
    void permissions_returns_401_withoutAuth() throws Exception {
        mvc.perform(get("/api/v1/tenants/app1/permissions"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void roles_list_returns_401_withoutAuth() throws Exception {
        mvc.perform(get("/api/v1/tenants/app1/roles"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void create_returns_401_withoutAuth() throws Exception {
        mvc.perform(post("/api/v1/tenants/app1/roles")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"R\",\"permissions\":[]}"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void permissions_returns_403_whenCantSeeTenant() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(anyString())).thenReturn(false);
        mvc.perform(get("/api/v1/tenants/app1/permissions").with(jwt()))
            .andExpect(status().isForbidden());
    }

    @Test
    void create_returns_403_whenCantManageTenant_evenIfCanSee() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(anyString())).thenReturn(true);
        when(tenantSecurity.canManageTenant(anyString())).thenReturn(false);
        mvc.perform(post("/api/v1/tenants/app1/roles")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Manager\",\"permissions\":[]}"))
            .andExpect(status().isForbidden());
    }

    @Test
    void crossTenant_isForbidden() throws Exception {
        // Caller is admin of "other"; trying to manage "app1".
        when(tenantSecurity.canSeeTenantBySlug(eq("app1"))).thenReturn(false);
        mvc.perform(get("/api/v1/tenants/app1/roles").with(jwt()))
            .andExpect(status().isForbidden());
    }

    // ---- happy paths ----

    @Test
    void permissions_returns_200_andList() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq("app1"))).thenReturn(true);
        when(rolesService.listPermissions(eq("app1"))).thenReturn(List.of(
            new PermissionDto("orders", "order:view", "View orders"),
            new PermissionDto("orders", "order:approve", "Approve orders")
        ));
        mvc.perform(get("/api/v1/tenants/app1/permissions").with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$[0].client").value("orders"))
            .andExpect(jsonPath("$[0].name").value("order:view"))
            .andExpect(jsonPath("$[1].name").value("order:approve"));
    }

    @Test
    void list_returns_200() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq("app1"))).thenReturn(true);
        when(rolesService.list(eq("app1"))).thenReturn(List.of(
            new RoleDto("Order Manager", "approves orders",
                List.of(new PermissionDto("orders", "order:approve")), 2, false)
        ));
        mvc.perform(get("/api/v1/tenants/app1/roles").with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$[0].name").value("Order Manager"))
            .andExpect(jsonPath("$[0].userCount").value(2))
            .andExpect(jsonPath("$[0].permissions[0].name").value("order:approve"));
    }

    @Test
    void create_returns_201_andLocationHeader() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq("app1"))).thenReturn(true);
        when(tenantSecurity.canManageTenant(eq("app1"))).thenReturn(true);
        when(rolesService.create(eq("app1"), any(CreateRoleRequest.class), anyString()))
            .thenReturn(new RoleDto("Order Manager", "approves",
                List.of(new PermissionDto("orders", "order:approve")), 0, false));

        mvc.perform(post("/api/v1/tenants/app1/roles")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "name": "Order Manager",
                      "description": "approves",
                      "permissions": [{"client":"orders","name":"order:approve"}]
                    }
                    """))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.name").value("Order Manager"))
            .andExpect(jsonPath("$.userCount").value(0));
    }

    @Test
    void create_returns_400_onMissingName() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq("app1"))).thenReturn(true);
        when(tenantSecurity.canManageTenant(eq("app1"))).thenReturn(true);
        mvc.perform(post("/api/v1/tenants/app1/roles")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"permissions\":[]}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void update_returns_200() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq("app1"))).thenReturn(true);
        when(tenantSecurity.canManageTenant(eq("app1"))).thenReturn(true);
        when(rolesService.update(eq("app1"), eq("Order Manager"), any(UpdateRoleRequest.class), anyString()))
            .thenReturn(new RoleDto("Order Manager", "updated", List.of(), 0, false));

        mvc.perform(put("/api/v1/tenants/app1/roles/Order Manager")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"description\":\"updated\",\"permissions\":[]}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.description").value("updated"));
    }

    @Test
    void delete_returns_204_onSuccess() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq("app1"))).thenReturn(true);
        when(tenantSecurity.canManageTenant(eq("app1"))).thenReturn(true);

        mvc.perform(delete("/api/v1/tenants/app1/roles/Order Manager").with(jwt()))
            .andExpect(status().isNoContent());
    }

    @Test
    void delete_returns_409_whenRoleInUse() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq("app1"))).thenReturn(true);
        when(tenantSecurity.canManageTenant(eq("app1"))).thenReturn(true);
        doThrow(new RoleInUseException("Order Manager", 3))
            .when(rolesService).delete(eq("app1"), eq("Order Manager"), anyString());

        mvc.perform(delete("/api/v1/tenants/app1/roles/Order Manager").with(jwt()))
            .andExpect(status().isConflict())
            .andExpect(jsonPath("$.error").value("role_in_use"))
            .andExpect(jsonPath("$.userCount").value(3));
    }

    @Test
    void delete_returns_404_whenRoleMissing() throws Exception {
        when(tenantSecurity.canSeeTenantBySlug(eq("app1"))).thenReturn(true);
        when(tenantSecurity.canManageTenant(eq("app1"))).thenReturn(true);
        doThrow(new RoleNotFoundException("Ghost"))
            .when(rolesService).delete(eq("app1"), eq("Ghost"), anyString());

        mvc.perform(delete("/api/v1/tenants/app1/roles/Ghost").with(jwt()))
            .andExpect(status().isNotFound());
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
            classes = {RolesController.class, GlobalExceptionHandler.class}
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
