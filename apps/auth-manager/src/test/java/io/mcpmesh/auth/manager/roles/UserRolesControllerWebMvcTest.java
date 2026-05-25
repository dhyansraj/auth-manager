package io.mcpmesh.auth.manager.roles;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mcpmesh.auth.manager.api.GlobalExceptionHandler;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.security.Permissions;
import io.mcpmesh.auth.manager.security.TenantSecurity;
import io.mcpmesh.auth.manager.service.TenantService;
import io.mcpmesh.auth.manager.service.UserManagementService;
import io.mcpmesh.auth.manager.api.dto.UserResponse;
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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
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
    @MockitoBean UserManagementService userManagementService;
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
        when(perms.hasOnTenant(anyString(), eq("USER_LIST"))).thenReturn(false);
        mvc.perform(get("/api/v1/tenants/app1/users/" + USER_ID).with(jwt()))
            .andExpect(status().isForbidden());
    }

    @Test
    void put_returns_403_whenCantManageUsersInTenant() throws Exception {
        when(perms.hasOnTenant(anyString(), eq("USER_REALM_ROLE_ASSIGN"))).thenReturn(false);
        mvc.perform(put("/api/v1/tenants/app1/users/" + USER_ID + "/roles")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roleNames\":[]}"))
            .andExpect(status().isForbidden());
    }

    @Test
    void put_returns_200_forTenantUserManager() throws Exception {
        // tenant-user-manager is the lighter-weight alternative to tenant-admin
        // and must succeed on user-management write endpoints.
        when(perms.hasOnTenant(eq(SLUG), eq("USER_REALM_ROLE_ASSIGN"))).thenReturn(true);
        when(perms.hasOnTenant(eq(SLUG), eq("USER_LIST"))).thenReturn(true);
        when(rolesService.updateUserRoles(eq(SLUG), eq(USER_ID), eq(List.of("Order Manager")), anyString()))
            .thenReturn(new RolesService.AssignResult(List.of("Order Manager"), List.of()));
        when(rolesService.userManageableRealmRoles(eq(SLUG), eq(USER_ID)))
            .thenReturn(List.of("Order Manager"));

        mvc.perform(put("/api/v1/tenants/app1/users/" + USER_ID + "/roles")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roleNames\":[\"Order Manager\"]}"))
            .andExpect(status().isOk());
    }

    // ---- happy paths ----

    @Test
    void get_returns_200_withRealmRoles() throws Exception {
        when(perms.hasOnTenant(eq(SLUG), eq("USER_LIST"))).thenReturn(true);
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
        when(perms.hasOnTenant(eq(SLUG), eq("USER_REALM_ROLE_ASSIGN"))).thenReturn(true);
        when(perms.hasOnTenant(eq(SLUG), eq("USER_LIST"))).thenReturn(true);
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
        when(perms.hasOnTenant(eq(SLUG), eq("USER_REALM_ROLE_ASSIGN"))).thenReturn(true);
        when(perms.hasOnTenant(eq(SLUG), eq("USER_LIST"))).thenReturn(true);
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
        when(perms.hasOnTenant(eq(SLUG), eq("USER_REALM_ROLE_ASSIGN"))).thenReturn(true);
        when(perms.hasOnTenant(eq(SLUG), eq("USER_LIST"))).thenReturn(true);
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
        when(perms.hasOnTenant(eq(SLUG), eq("USER_REALM_ROLE_ASSIGN"))).thenReturn(true);

        mvc.perform(put("/api/v1/tenants/app1/users/" + USER_ID + "/roles")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            .andExpect(status().isBadRequest());
    }

    // ---- slug-keyed list endpoint ----

    @Test
    void list_returns_401_withoutAuth() throws Exception {
        mvc.perform(get("/api/v1/tenants/app1/users"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void list_returns_403_whenMissingUserList() throws Exception {
        when(perms.hasOnTenant(anyString(), eq("USER_LIST"))).thenReturn(false);
        mvc.perform(get("/api/v1/tenants/app1/users").with(jwt()))
            .andExpect(status().isForbidden());
    }

    @Test
    void list_returns_200_withItems() throws Exception {
        when(perms.hasOnTenant(eq(SLUG), eq("USER_LIST"))).thenReturn(true);

        UserResponse u1 = sampleUser("u-1", "alice", List.of("user-viewer"),
            List.of("inspector"));
        UserResponse u2 = sampleUser("u-2", "bob", List.of("user-viewer"),
            List.of("inspector"));
        when(userManagementService.listWithRoles(eq(SLUG), eq(null), eq(null),
            eq(0), eq(50), eq(true)))
            .thenReturn(new UserManagementService.ListResult(List.of(u1, u2), 0, 50, 2));

        mvc.perform(get("/api/v1/tenants/app1/users").with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.items.length()").value(2))
            .andExpect(jsonPath("$.items[0].id").value("u-1"))
            .andExpect(jsonPath("$.items[0].realmRoles[0]").value("inspector"))
            .andExpect(jsonPath("$.totalItems").value(2));
    }

    @Test
    void list_withRoleFilter_passesRoleThrough() throws Exception {
        when(perms.hasOnTenant(eq(SLUG), eq("USER_LIST"))).thenReturn(true);

        UserResponse u1 = sampleUser("u-1", "alice", List.of("user-viewer"),
            List.of("inspector"));
        when(userManagementService.listWithRoles(eq(SLUG), eq("inspector"), eq(null),
            eq(0), eq(50), eq(true)))
            .thenReturn(new UserManagementService.ListResult(List.of(u1), 0, 50, 1));

        mvc.perform(get("/api/v1/tenants/app1/users").param("role", "inspector").with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.items.length()").value(1))
            .andExpect(jsonPath("$.items[0].realmRoles[0]").value("inspector"));
    }

    @Test
    void list_withUnknownRole_returnsEmpty() throws Exception {
        when(perms.hasOnTenant(eq(SLUG), eq("USER_LIST"))).thenReturn(true);
        when(userManagementService.listWithRoles(eq(SLUG), eq("nonexistent"), eq(null),
            eq(0), eq(50), eq(true)))
            .thenReturn(new UserManagementService.ListResult(List.of(), 0, 50, 0));

        mvc.perform(get("/api/v1/tenants/app1/users").param("role", "nonexistent").with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.items.length()").value(0))
            .andExpect(jsonPath("$.totalItems").value(0));
    }

    @Test
    void list_withoutRealmRoles_omitsRealmRolesField() throws Exception {
        when(perms.hasOnTenant(eq(SLUG), eq("USER_LIST"))).thenReturn(true);

        UserResponse u1 = sampleUser("u-1", "alice", List.of("user-viewer"), null);
        when(userManagementService.listWithRoles(eq(SLUG), eq(null), eq(null),
            eq(0), eq(50), eq(false)))
            .thenReturn(new UserManagementService.ListResult(List.of(u1), 0, 50, 1));

        mvc.perform(get("/api/v1/tenants/app1/users")
                .param("includeRealmRoles", "false")
                .with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.items[0].id").value("u-1"))
            // realmRoles is @JsonInclude(NON_NULL) -- a null field is omitted.
            .andExpect(jsonPath("$.items[0].realmRoles").doesNotExist());
    }

    private static UserResponse sampleUser(String id, String username,
                                           List<String> sysRoles, List<String> realmRoles) {
        UserRepresentation u = new UserRepresentation();
        u.setId(id);
        u.setUsername(username);
        u.setEmail(username + "@app1.test");
        u.setFirstName(username);
        u.setLastName("Doe");
        u.setEnabled(true);
        u.setEmailVerified(true);
        return realmRoles == null
            ? UserResponse.from(u, sysRoles)
            : UserResponse.from(u, sysRoles, realmRoles);
    }

    // ---- systemRoles privileged path ----

    @Test
    void put_withSystemRoles_returns_403_whenCallerCanManageUsersButNotTenant() throws Exception {
        // Lighter gate passes; stricter gate (USER_SYSTEM_ROLE_ASSIGN) fails.
        // Caller is a tenant-user-manager trying to mint a tenant-admin.
        when(perms.hasOnTenant(eq(SLUG), eq("USER_REALM_ROLE_ASSIGN"))).thenReturn(true);
        when(perms.hasOnTenant(eq(SLUG), eq("USER_SYSTEM_ROLE_ASSIGN"))).thenReturn(false);

        mvc.perform(put("/api/v1/tenants/app1/users/" + USER_ID + "/roles")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roleNames\":[],\"systemRoles\":[\"tenant-admin\"]}"))
            .andExpect(status().isForbidden());
    }

    @Test
    void put_withSystemRoles_returns_200_forTenantAdmin_andTriggersBothUpdaters() throws Exception {
        when(perms.hasOnTenant(eq(SLUG), eq("USER_REALM_ROLE_ASSIGN"))).thenReturn(true);
        when(perms.hasOnTenant(eq(SLUG), eq("USER_SYSTEM_ROLE_ASSIGN"))).thenReturn(true);
        when(perms.hasOnTenant(eq(SLUG), eq("USER_LIST"))).thenReturn(true);
        when(rolesService.updateUserRoles(eq(SLUG), eq(USER_ID), eq(List.of()), anyString()))
            .thenReturn(new RolesService.AssignResult(List.of(), List.of()));
        when(rolesService.updateUserSystemRoles(eq(SLUG), eq(USER_ID), eq(List.of("tenant-admin")), anyString()))
            .thenReturn(new RolesService.AssignResult(List.of("tenant-admin"), List.of()));
        when(rolesService.userManageableRealmRoles(eq(SLUG), eq(USER_ID)))
            .thenReturn(List.of());

        mvc.perform(put("/api/v1/tenants/app1/users/" + USER_ID + "/roles")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roleNames\":[],\"systemRoles\":[\"tenant-admin\"]}"))
            .andExpect(status().isOk());

        verify(rolesService).updateUserSystemRoles(eq(SLUG), eq(USER_ID),
            eq(List.of("tenant-admin")), anyString());
    }

    @Test
    void put_withoutSystemRoles_skipsSystemUpdater_evenWhenCanManageTenant() throws Exception {
        // When systemRoles is omitted, the privileged path is NOT triggered
        // and the service's updateUserSystemRoles must not be invoked --
        // ensures backward-compat: callers that only manage composite roles
        // see no change in behavior.
        when(perms.hasOnTenant(eq(SLUG), eq("USER_REALM_ROLE_ASSIGN"))).thenReturn(true);
        when(perms.hasOnTenant(eq(SLUG), eq("USER_LIST"))).thenReturn(true);
        when(rolesService.updateUserRoles(eq(SLUG), eq(USER_ID), eq(List.of("Order Manager")), anyString()))
            .thenReturn(new RolesService.AssignResult(List.of("Order Manager"), List.of()));
        when(rolesService.userManageableRealmRoles(eq(SLUG), eq(USER_ID)))
            .thenReturn(List.of("Order Manager"));

        mvc.perform(put("/api/v1/tenants/app1/users/" + USER_ID + "/roles")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"roleNames\":[\"Order Manager\"]}"))
            .andExpect(status().isOk());

        verify(rolesService, never()).updateUserSystemRoles(anyString(), anyString(), any(), anyString());
    }

    // ---- UUID-shaped path must NOT route to this controller ----

    @Test
    void list_withUuidSlug_doesNotRouteHere() throws Exception {
        // UUID-shaped paths must be excluded by the @RequestMapping regex so
        // they fall through to the sibling UUID-keyed UserManagementController
        // (not loaded in this slice -> expect 404, not the usual 401/403 from
        // the slug controller's security gates).
        String uuid = "82f708a4-742b-46b5-bf87-ecf41b66d0bd";
        mvc.perform(get("/api/v1/tenants/" + uuid + "/users").with(jwt()))
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
