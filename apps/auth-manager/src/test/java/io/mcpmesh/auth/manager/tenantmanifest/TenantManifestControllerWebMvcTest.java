package io.mcpmesh.auth.manager.tenantmanifest;

import io.mcpmesh.auth.manager.api.GlobalExceptionHandler;
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
import org.springframework.http.HttpHeaders;
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

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MVC-layer test for {@link TenantManifestController}. Mirrors
 * {@code RolesControllerWebMvcTest}: stripped-down boot context, mocked
 * service + tenant-security, real Spring Security filter chain so
 * {@code @PreAuthorize} runs.
 */
@SpringBootTest(
    classes = TenantManifestControllerWebMvcTest.TestApp.class,
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
class TenantManifestControllerWebMvcTest {

    @MockitoBean TenantManifestService manifestService;
    @MockitoBean TenantManifestApplyService applyService;
    @MockitoBean(name = "tenantSecurity") TenantSecurity tenantSecurity;
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

    private static TenantManifest sampleManifest() {
        return new TenantManifest(
            new TenantManifest.Meta("safesound", "t-safesound",
                Instant.parse("2026-05-23T10:30:00Z"), "v1"),
            List.of(
                new TenantManifest.PermissionEntry(
                    "BOOKING_VIEW_OWN", "View bookings I created", "safesound-backend"),
                new TenantManifest.PermissionEntry(
                    "HOME_VIEW_OWN", "View homes the caller owns", "safesound-backend")
            ),
            List.of(
                new TenantManifest.RoleEntry(
                    "customer", "Default role for self-signup users",
                    List.of("BOOKING_VIEW_OWN", "HOME_VIEW_OWN"))
            )
        );
    }

    // ---- auth gating ----

    @Test
    void manifest_returns_401_withoutAuth() throws Exception {
        mvc.perform(get("/api/v1/tenants/safesound/manifest"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void manifest_returns_403_whenCantSeeTenant() throws Exception {
        when(perms.hasOnTenant(anyString(), eq("MANIFEST_APPLY"))).thenReturn(false);
        mvc.perform(get("/api/v1/tenants/safesound/manifest").with(jwt()))
            .andExpect(status().isForbidden());
    }

    // ---- happy paths ----

    @Test
    void manifest_returns_200_yaml_byDefault() throws Exception {
        when(perms.hasOnTenant(eq("safesound"), eq("MANIFEST_APPLY"))).thenReturn(true);
        when(manifestService.generate(eq("safesound"))).thenReturn(sampleManifest());

        var result = mvc.perform(get("/api/v1/tenants/safesound/manifest").with(jwt()))
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith("application/yaml"))
            .andReturn();

        String body = result.getResponse().getContentAsString();
        // Sanity: no leading "---" doc-start, top-level keys present, value
        // appears under the right block.
        org.assertj.core.api.Assertions.assertThat(body).doesNotStartWith("---");
        org.assertj.core.api.Assertions.assertThat(body).contains("meta:");
        org.assertj.core.api.Assertions.assertThat(body).contains("permissions:");
        org.assertj.core.api.Assertions.assertThat(body).contains("roles:");
        org.assertj.core.api.Assertions.assertThat(body).contains("tenantSlug: safesound");
        org.assertj.core.api.Assertions.assertThat(body).contains("realmName: t-safesound");
        org.assertj.core.api.Assertions.assertThat(body).contains("version: v1");
        org.assertj.core.api.Assertions.assertThat(body).contains("BOOKING_VIEW_OWN");
        org.assertj.core.api.Assertions.assertThat(body).contains("HOME_VIEW_OWN");
        org.assertj.core.api.Assertions.assertThat(body).contains("- BOOKING_VIEW_OWN");
    }

    @Test
    void manifest_returns_json_whenFormatJson() throws Exception {
        when(perms.hasOnTenant(eq("safesound"), eq("MANIFEST_APPLY"))).thenReturn(true);
        when(manifestService.generate(eq("safesound"))).thenReturn(sampleManifest());

        mvc.perform(get("/api/v1/tenants/safesound/manifest")
                .param("format", "json")
                .with(jwt()))
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.meta.tenantSlug").value("safesound"))
            .andExpect(jsonPath("$.meta.realmName").value("t-safesound"))
            .andExpect(jsonPath("$.meta.version").value("v1"))
            .andExpect(jsonPath("$.permissions[0].id").value("BOOKING_VIEW_OWN"))
            .andExpect(jsonPath("$.roles[0].name").value("customer"))
            .andExpect(jsonPath("$.roles[0].permissions[0]").value("BOOKING_VIEW_OWN"));
    }

    @Test
    void manifest_returns_json_whenAcceptHeaderIsJson() throws Exception {
        when(perms.hasOnTenant(eq("safesound"), eq("MANIFEST_APPLY"))).thenReturn(true);
        when(manifestService.generate(eq("safesound"))).thenReturn(sampleManifest());

        mvc.perform(get("/api/v1/tenants/safesound/manifest")
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .with(jwt()))
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.meta.tenantSlug").value("safesound"));
    }

    @Test
    void manifest_returns_yaml_whenAcceptHeaderIsYaml() throws Exception {
        when(perms.hasOnTenant(eq("safesound"), eq("MANIFEST_APPLY"))).thenReturn(true);
        when(manifestService.generate(eq("safesound"))).thenReturn(sampleManifest());

        mvc.perform(get("/api/v1/tenants/safesound/manifest")
                .header(HttpHeaders.ACCEPT, "application/yaml")
                .with(jwt()))
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith("application/yaml"));
    }

    // ---- test app ----

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @ComponentScan(
        basePackages = {
            "io.mcpmesh.auth.manager.tenantmanifest",
            "io.mcpmesh.auth.manager.api"
        },
        useDefaultFilters = false,
        includeFilters = @ComponentScan.Filter(
            type = FilterType.ASSIGNABLE_TYPE,
            classes = {TenantManifestController.class, GlobalExceptionHandler.class}
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
