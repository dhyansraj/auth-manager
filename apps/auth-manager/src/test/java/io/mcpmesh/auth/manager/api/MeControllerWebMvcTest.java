package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
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
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MVC-layer test for {@link MeController}. Same skinny-context pattern as
 * the rest of the auth-manager WebMvc tests so this stays in surefire.
 *
 * <p>Coverage focuses on the three branches that {@code MeController}
 * actually has logic for:
 * <ul>
 *   <li>platform-admin: context=platform, tenant=null, platform capabilities only</li>
 *   <li>tenant-admin: context=tenant, tenant populated, tenant capabilities only</li>
 *   <li>plain authenticated tenant user: context=tenant, tenant populated, no caps</li>
 * </ul>
 */
@SpringBootTest(
    classes = MeControllerWebMvcTest.TestApp.class,
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
class MeControllerWebMvcTest {

    private static final UUID APP1_ID = UUID.randomUUID();

    @MockitoBean(name = "tenantSecurity") TenantSecurity tenantSecurity;
    @MockitoBean TenantRepository tenantRepository;

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
        mvc.perform(get("/api/v1/me"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void me_for_platform_admin_returns_platform_context_with_platform_caps() throws Exception {
        when(tenantSecurity.isPlatformAdmin()).thenReturn(true);

        mvc.perform(get("/api/v1/me").with(jwt().jwt(j -> j
                .subject("platform-admin-sub")
                .claim("email", "admin@platform.test")
                .claim("preferred_username", "admin"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.context").value("platform"))
            .andExpect(jsonPath("$.tenant").doesNotExist())
            .andExpect(jsonPath("$.isPlatformAdmin").value(true))
            .andExpect(jsonPath("$.isTenantAdmin").value(false))
            .andExpect(jsonPath("$.user.id").value("platform-admin-sub"))
            .andExpect(jsonPath("$.permissions").value(org.hamcrest.Matchers.containsInAnyOrder(
                // PLATFORM_PERMS
                "TENANT_LIST_ALL", "TENANT_CREATE", "TENANT_DELETE",
                "GLOBAL_AUDIT_VIEW", "SYSTEM_CLIENT_MANAGE",
                // TENANT_ADMIN_BUNDLE (TENANT_CONFIG_PERMS + TENANT_USER_MGMT_PERMS + TENANT_SYSTEM_ROLE_PERM)
                "TENANT_VIEW", "TENANT_EDIT", "ROUTES_EDIT", "IDP_EDIT",
                "BRANDING_EDIT", "EMAIL_EDIT", "EMAIL_SEND",
                "PERMISSIONS_EDIT", "ROLES_EDIT", "APPS_EDIT",
                "MANIFEST_APPLY",
                "USER_LIST", "USER_INVITE", "USER_DISABLE",
                "USER_REALM_ROLE_ASSIGN", "AUDIT_VIEW",
                "USER_SYSTEM_ROLE_ASSIGN")));
    }

    @Test
    void me_for_tenant_admin_returns_tenant_context_with_tenant_caps() throws Exception {
        when(tenantSecurity.isPlatformAdmin()).thenReturn(false);
        when(tenantSecurity.currentTenantId()).thenReturn(Optional.of(APP1_ID));
        when(tenantRepository.findById(APP1_ID)).thenReturn(Optional.of(
            tenantWith(APP1_ID, "app1", "App One")));

        // Simulate KC composite-role expansion: in production, tenant-admin
        // is a composite that KC flattens into the JWT's
        // resource_access.usermanagement.roles claim as the atomic perms
        // (TENANT_ADMIN_BUNDLE) plus the composite name itself.
        mvc.perform(get("/api/v1/me").with(jwt().jwt(j -> j
                .subject("alice-sub")
                .claim("email", "alice@app1.test")
                .claim("preferred_username", "alice@app1.test")
                .claim("resource_access", Map.of(
                    "usermanagement", Map.of("roles", List.of(
                        "tenant-admin",
                        "TENANT_VIEW", "ROUTES_EDIT",
                        "USER_INVITE", "AUDIT_VIEW")))))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.context").value("tenant"))
            .andExpect(jsonPath("$.tenant.id").value(APP1_ID.toString()))
            .andExpect(jsonPath("$.tenant.slug").value("app1"))
            .andExpect(jsonPath("$.tenant.displayName").value("App One"))
            .andExpect(jsonPath("$.tenant.realmName").value("t-app1"))
            .andExpect(jsonPath("$.isPlatformAdmin").value(false))
            .andExpect(jsonPath("$.isTenantAdmin").value(true))
            .andExpect(jsonPath("$.permissions").value(org.hamcrest.Matchers.containsInAnyOrder(
                "TENANT_VIEW", "ROUTES_EDIT", "USER_INVITE", "AUDIT_VIEW")));
    }

    @Test
    void me_for_plain_tenant_user_returns_tenant_context_with_no_caps() throws Exception {
        when(tenantSecurity.isPlatformAdmin()).thenReturn(false);
        when(tenantSecurity.currentTenantId()).thenReturn(Optional.of(APP1_ID));
        when(tenantRepository.findById(APP1_ID)).thenReturn(Optional.of(
            tenantWith(APP1_ID, "app1", "App One")));

        mvc.perform(get("/api/v1/me").with(jwt().jwt(j -> j
                .subject("bob-sub")
                .claim("email", "bob@app1.test")
                .claim("preferred_username", "bob@app1.test"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.context").value("tenant"))
            .andExpect(jsonPath("$.tenant.slug").value("app1"))
            .andExpect(jsonPath("$.isPlatformAdmin").value(false))
            .andExpect(jsonPath("$.isTenantAdmin").value(false))
            .andExpect(jsonPath("$.permissions.length()").value(0));
    }

    @Test
    void me_for_authenticated_user_with_no_resolvable_tenant_returns_null_tenant() throws Exception {
        // E.g. orphan JWT from a deleted tenant.
        when(tenantSecurity.isPlatformAdmin()).thenReturn(false);
        when(tenantSecurity.currentTenantId()).thenReturn(Optional.empty());

        mvc.perform(get("/api/v1/me").with(jwt().jwt(j -> j
                .subject("orphan-sub")
                .claim("email", "orphan@deleted.test")
                .claim("preferred_username", "orphan"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.context").value("tenant"))
            .andExpect(jsonPath("$.tenant").doesNotExist())
            .andExpect(jsonPath("$.isPlatformAdmin").value(false))
            .andExpect(jsonPath("$.isTenantAdmin").value(false))
            .andExpect(jsonPath("$.permissions.length()").value(0));
    }

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

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @ComponentScan(
        basePackages = "io.mcpmesh.auth.manager.api",
        useDefaultFilters = false,
        includeFilters = @ComponentScan.Filter(
            type = FilterType.ASSIGNABLE_TYPE,
            classes = {MeController.class, GlobalExceptionHandler.class}
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
