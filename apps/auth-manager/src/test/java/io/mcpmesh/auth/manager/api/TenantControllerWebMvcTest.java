package io.mcpmesh.auth.manager.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.IdentityProvidersBootstrap;
import io.mcpmesh.auth.manager.persistence.AuditEventRepository;
import io.mcpmesh.auth.manager.security.Permissions;
import io.mcpmesh.auth.manager.security.TenantSecurity;
import io.mcpmesh.auth.manager.service.TenantService;
import io.mcpmesh.auth.manager.service.UsermanagementBootstrap;
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
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MVC-layer test for {@link TenantController}, focused on tenant scoping
 * behavior (platform-admin sees all, tenant-admin sees only own tenant).
 *
 * <p>Uses a stripped-down boot context (no JPA / no Keycloak / no Postgres
 * / no Redis) so it stays in surefire. The production {@code SecurityConfig}
 * is replaced with {@link TestSecurityConfig} which requires authentication
 * on every request and accepts the test-minted JWTs from
 * {@code SecurityMockMvcRequestPostProcessors.jwt()}.
 */
@SpringBootTest(
    classes = TenantControllerWebMvcTest.TestApp.class,
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
class TenantControllerWebMvcTest {

    private static final UUID APP1_ID = UUID.randomUUID();
    private static final UUID APP2_ID = UUID.randomUUID();

    @MockitoBean TenantService tenantService;
    @MockitoBean AuditEventRepository auditRepo;
    @MockitoBean UsermanagementBootstrap bootstrap;
    @MockitoBean IdentityProvidersBootstrap idpBootstrap;
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

        when(tenantService.hostnamesFor(any(UUID.class))).thenReturn(List.of());
    }

    @Test
    void list_returns_401_without_auth() throws Exception {
        // No JWT in request -> @PreAuthorize("isAuthenticated()") denies and
        // the TestSecurityConfig entry-point returns 401. (In prod the chain
        // is permitAll() and Spring's AccessDeniedHandler returns 403 — the
        // status differs but the gate works either way.)
        mvc.perform(get("/api/v1/tenants"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void list_returns_all_tenants_for_platform_admin() throws Exception {
        when(tenantSecurity.isPlatformAdmin()).thenReturn(true);
        Tenant app1 = tenantWith(APP1_ID, "app1", "App 1");
        Tenant app2 = tenantWith(APP2_ID, "app2", "App 2");
        when(tenantService.list()).thenReturn(List.of(app1, app2));

        mvc.perform(get("/api/v1/tenants").with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(2))
            .andExpect(jsonPath("$[0].slug").value("app1"))
            .andExpect(jsonPath("$[1].slug").value("app2"));
    }

    @Test
    void list_returns_only_own_tenant_for_tenant_admin() throws Exception {
        when(tenantSecurity.isPlatformAdmin()).thenReturn(false);
        when(tenantSecurity.currentTenantId()).thenReturn(Optional.of(APP1_ID));
        Tenant app1 = tenantWith(APP1_ID, "app1", "App 1");
        when(tenantService.get(APP1_ID)).thenReturn(app1);

        mvc.perform(get("/api/v1/tenants").with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(1))
            .andExpect(jsonPath("$[0].slug").value("app1"));
    }

    @Test
    void list_returns_empty_for_authenticated_caller_without_tenant() throws Exception {
        // E.g. a JWT from a tenant realm whose backing row has been removed.
        when(tenantSecurity.isPlatformAdmin()).thenReturn(false);
        when(tenantSecurity.currentTenantId()).thenReturn(Optional.empty());

        mvc.perform(get("/api/v1/tenants").with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void getBySlug_returns_403_when_caller_cannot_see_tenant() throws Exception {
        // tenant-admin of app1 trying to fetch app2 — Permissions returns false.
        when(perms.hasOnTenant(eq("app2"), eq("TENANT_VIEW"))).thenReturn(false);

        mvc.perform(get("/api/v1/tenants/by-slug/app2").with(jwt()))
            .andExpect(status().isForbidden());
    }

    @Test
    void getBySlug_returns_200_when_caller_can_see_tenant() throws Exception {
        when(perms.hasOnTenant(eq("app1"), eq("TENANT_VIEW"))).thenReturn(true);
        Tenant app1 = tenantWith(APP1_ID, "app1", "App 1");
        when(tenantService.getBySlug("app1")).thenReturn(app1);

        mvc.perform(get("/api/v1/tenants/by-slug/app1").with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.slug").value("app1"));
    }

    @Test
    void getById_returns_403_when_caller_cannot_see_tenant() throws Exception {
        when(perms.hasOnTenantId(eq(APP2_ID), eq("TENANT_VIEW"))).thenReturn(false);

        mvc.perform(get("/api/v1/tenants/{id}", APP2_ID).with(jwt()))
            .andExpect(status().isForbidden());
    }

    @Test
    void getById_returns_200_when_caller_can_see_tenant() throws Exception {
        when(perms.hasOnTenantId(eq(APP1_ID), eq("TENANT_VIEW"))).thenReturn(true);
        Tenant app1 = tenantWith(APP1_ID, "app1", "App 1");
        when(tenantService.get(APP1_ID)).thenReturn(app1);

        mvc.perform(get("/api/v1/tenants/{id}", APP1_ID).with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.slug").value("app1"));
    }

    /**
     * Build a Tenant pojo with the fields TenantResponse.from() needs.
     * We bypass the ctor so we can set id/status/realmName directly via
     * reflection equivalents that the entity exposes only through markActive.
     */
    private static Tenant tenantWith(UUID id, String slug, String displayName) {
        Tenant t;
        try {
            var ctor = Tenant.class.getDeclaredConstructor(
                String.class, String.class, String.class, java.util.Map.class);
            ctor.setAccessible(true);
            t = ctor.newInstance(slug, displayName, "system", new HashMap<String, Object>());
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
        // markActive sets status=ACTIVE + realmName
        t.markActive("t-" + slug);
        setField(t, "id", id);
        setField(t, "createdAt", Instant.now());
        setField(t, "updatedAt", Instant.now());
        return t;
    }

    private static void setField(Object target, String name, Object value) {
        try {
            var f = target.getClass().getDeclaredField(name);
            f.setAccessible(true);
            f.set(target, value);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
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
            classes = {TenantController.class, GlobalExceptionHandler.class}
        )
    )
    @Import(TestSecurityConfig.class)
    static class TestApp {
    }

    @Configuration
    @EnableMethodSecurity
    static class TestSecurityConfig {

        /**
         * Slice security: require auth and return 401 on missing auth. The
         * {@code jwt()} request-post-processor in the tests injects a
         * {@link org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken}
         * directly into the security context, so it satisfies
         * {@code anyRequest().authenticated()} without going through any
         * OAuth2 decoder.
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
