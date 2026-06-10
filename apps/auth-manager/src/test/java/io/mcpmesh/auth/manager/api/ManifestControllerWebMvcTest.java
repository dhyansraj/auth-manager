package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.domain.app.AppManifest;
import io.mcpmesh.auth.manager.security.Permissions;
import io.mcpmesh.auth.manager.service.ManifestService;
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
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MVC-layer test for {@link ManifestController}'s authorization gates,
 * which were previously absent entirely (anonymous access). Apply gates
 * on {@code MANIFEST_APPLY}; the list GET gates on {@code APPS_EDIT}
 * like the sibling {@link AppController}. Both via
 * {@code @perms.hasOnTenantId} (platform-admin bypass included).
 */
@SpringBootTest(
    classes = ManifestControllerWebMvcTest.TestApp.class,
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
class ManifestControllerWebMvcTest {

    private static final UUID TENANT_ID = UUID.randomUUID();
    private static final UUID APP_ID = UUID.randomUUID();
    private static final String MANIFEST_JSON =
        "{\"roles\":[\"admin\"],\"resources\":[],\"rolePermissions\":{}}";

    @MockitoBean ManifestService manifestService;
    @MockitoBean(name = "perms") Permissions perms;

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
    void apply_returns_401_without_auth() throws Exception {
        mvc.perform(post("/api/v1/tenants/{t}/apps/{a}/manifests/apply", TENANT_ID, APP_ID)
                .contentType(MediaType.APPLICATION_JSON)
                .content(MANIFEST_JSON))
            .andExpect(status().isUnauthorized());

        verifyNoInteractions(manifestService);
    }

    @Test
    void apply_returns_403_for_tenant_user_without_manifest_apply() throws Exception {
        when(perms.hasOnTenantId(eq(TENANT_ID), eq("MANIFEST_APPLY"))).thenReturn(false);

        mvc.perform(post("/api/v1/tenants/{t}/apps/{a}/manifests/apply", TENANT_ID, APP_ID)
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content(MANIFEST_JSON))
            .andExpect(status().isForbidden());

        verifyNoInteractions(manifestService);
    }

    @Test
    void apply_succeeds_and_records_caller_as_actor() throws Exception {
        when(perms.hasOnTenantId(eq(TENANT_ID), eq("MANIFEST_APPLY"))).thenReturn(true);
        var stored = new AppManifest(APP_ID, 1, "roles: [admin]",
            Map.of("roles", List.of("admin")), "a".repeat(64), "alice");
        when(manifestService.apply(eq(TENANT_ID), eq(APP_ID), any(), eq("alice")))
            .thenReturn(new ManifestService.ApplyResult(stored, false));

        mvc.perform(post("/api/v1/tenants/{t}/apps/{a}/manifests/apply", TENANT_ID, APP_ID)
                .with(jwt().jwt(j -> j.claim("preferred_username", "alice")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(MANIFEST_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.appliedBy").value("alice"))
            .andExpect(jsonPath("$.noOp").value(false));

        verify(manifestService).apply(eq(TENANT_ID), eq(APP_ID), any(), eq("alice"));
    }

    @Test
    void list_returns_401_without_auth() throws Exception {
        mvc.perform(get("/api/v1/tenants/{t}/apps/{a}/manifests", TENANT_ID, APP_ID))
            .andExpect(status().isUnauthorized());

        verifyNoInteractions(manifestService);
    }

    @Test
    void list_returns_403_for_tenant_user_without_apps_edit() throws Exception {
        when(perms.hasOnTenantId(eq(TENANT_ID), eq("APPS_EDIT"))).thenReturn(false);

        mvc.perform(get("/api/v1/tenants/{t}/apps/{a}/manifests", TENANT_ID, APP_ID)
                .with(jwt()))
            .andExpect(status().isForbidden());

        verifyNoInteractions(manifestService);
    }

    @Test
    void list_returns_200_for_apps_edit_holder() throws Exception {
        when(perms.hasOnTenantId(eq(TENANT_ID), eq("APPS_EDIT"))).thenReturn(true);
        when(manifestService.listForApp(TENANT_ID, APP_ID)).thenReturn(List.of());

        mvc.perform(get("/api/v1/tenants/{t}/apps/{a}/manifests", TENANT_ID, APP_ID)
                .with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(0));
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @ComponentScan(
        basePackages = "io.mcpmesh.auth.manager.api",
        useDefaultFilters = false,
        includeFilters = @ComponentScan.Filter(
            type = FilterType.ASSIGNABLE_TYPE,
            classes = {ManifestController.class, GlobalExceptionHandler.class}
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
