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
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MVC-layer test for {@link TenantManifestController#apply}. Mirrors the
 * stripped-down setup of the GET endpoint's test.
 */
@SpringBootTest(
    classes = TenantManifestApplyControllerWebMvcTest.TestApp.class,
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
class TenantManifestApplyControllerWebMvcTest {

    private static final String JSON_BODY = """
        {
          "permissions": [
            {"id":"HOME_VIEW_OWN","description":"View homes the caller owns","client":"safesound-backend"}
          ],
          "roles": [
            {"name":"customer","description":"Default role","permissions":["HOME_VIEW_OWN"]}
          ]
        }
        """;

    private static final String YAML_BODY = """
        permissions:
          - id: HOME_VIEW_OWN
            description: View homes the caller owns
            client: safesound-backend
        roles:
          - name: customer
            description: Default role
            permissions:
              - HOME_VIEW_OWN
        """;

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

    private static ApplyResult okResult() {
        return new ApplyResult(
            false,
            new ApplyResult.Diff(List.of("HOME_VIEW_OWN"), List.of(), List.of(), List.of()),
            null,
            null,
            List.of()
        );
    }

    // ---- auth gating ----

    @Test
    void apply_returns_401_withoutAuth() throws Exception {
        mvc.perform(post("/api/v1/tenants/safesound/manifest:apply")
                .contentType(MediaType.APPLICATION_JSON)
                .content(JSON_BODY))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void apply_returns_403_whenCantManageTenant() throws Exception {
        when(perms.hasOnTenant(anyString(), eq("MANIFEST_APPLY"))).thenReturn(false);
        mvc.perform(post("/api/v1/tenants/safesound/manifest:apply")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content(JSON_BODY))
            .andExpect(status().isForbidden());
    }

    // ---- happy paths ----

    @Test
    void apply_returns_200_andApplyResultJson_onJsonBody() throws Exception {
        when(perms.hasOnTenant(eq("safesound"), eq("MANIFEST_APPLY"))).thenReturn(true);
        when(applyService.apply(eq("safesound"), any(TenantManifest.class),
                anyBoolean(), anyBoolean(), anyBoolean(), anyString()))
            .thenReturn(okResult());

        mvc.perform(post("/api/v1/tenants/safesound/manifest:apply")
                .with(jwt())
                .contentType(MediaType.APPLICATION_JSON)
                .content(JSON_BODY))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.dryRun").value(false))
            .andExpect(jsonPath("$.permissions.created[0]").value("HOME_VIEW_OWN"))
            .andExpect(jsonPath("$.permissions.updated").isArray())
            .andExpect(jsonPath("$.warnings").isArray());
    }

    @Test
    void apply_parsesYamlBody() throws Exception {
        when(perms.hasOnTenant(eq("safesound"), eq("MANIFEST_APPLY"))).thenReturn(true);
        when(applyService.apply(eq("safesound"), any(TenantManifest.class),
                anyBoolean(), anyBoolean(), anyBoolean(), anyString()))
            .thenReturn(okResult());

        mvc.perform(post("/api/v1/tenants/safesound/manifest:apply")
                .with(jwt())
                .contentType(TenantManifestController.APPLICATION_YAML_VALUE)
                .content(YAML_BODY))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.permissions.created[0]").value("HOME_VIEW_OWN"));
    }

    // ---- tripwire ----

    @Test
    void apply_returns_409_whenTripwireFires_withoutForce() throws Exception {
        when(perms.hasOnTenant(eq("safesound"), eq("MANIFEST_APPLY"))).thenReturn(true);
        ApplyResult trippedBody = new ApplyResult(
            false,
            ApplyResult.Diff.empty(),
            ApplyResult.Diff.empty(),
            new ApplyResult.HashTripwireResult("sha256:old", "sha256:new", false, true, null),
            List.of()
        );
        when(applyService.apply(eq("safesound"), any(TenantManifest.class),
                eq(true), eq(false), eq(false), anyString()))
            .thenThrow(new TenantManifestApplyService.TripwireException(trippedBody));

        mvc.perform(post("/api/v1/tenants/safesound/manifest:apply")
                .with(jwt())
                .param("applyRoles", "true")
                .contentType(MediaType.APPLICATION_JSON)
                .content(JSON_BODY))
            .andExpect(status().isConflict())
            .andExpect(jsonPath("$.hashTripwire.tripped").value(true))
            .andExpect(jsonPath("$.hashTripwire.match").value(false))
            .andExpect(jsonPath("$.hashTripwire.storedHash").value("sha256:old"))
            .andExpect(jsonPath("$.hashTripwire.currentHash").value("sha256:new"));
    }

    @Test
    void apply_returns_200_whenTripwireFires_withForce() throws Exception {
        when(perms.hasOnTenant(eq("safesound"), eq("MANIFEST_APPLY"))).thenReturn(true);
        ApplyResult appliedBody = new ApplyResult(
            false,
            ApplyResult.Diff.empty(),
            new ApplyResult.Diff(List.of("customer"), List.of(), List.of(), List.of()),
            new ApplyResult.HashTripwireResult("sha256:old", "sha256:new", false, true, "sha256:final"),
            List.of()
        );
        when(applyService.apply(eq("safesound"), any(TenantManifest.class),
                eq(true), eq(true), eq(false), anyString()))
            .thenReturn(appliedBody);

        mvc.perform(post("/api/v1/tenants/safesound/manifest:apply")
                .with(jwt())
                .param("applyRoles", "true")
                .param("force", "true")
                .contentType(MediaType.APPLICATION_JSON)
                .content(JSON_BODY))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.hashTripwire.tripped").value(true))
            .andExpect(jsonPath("$.hashTripwire.newHashAfterApply").value("sha256:final"))
            .andExpect(jsonPath("$.roles.created[0]").value("customer"));
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
