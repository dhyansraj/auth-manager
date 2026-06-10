package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.security.Permissions;
import io.mcpmesh.auth.manager.service.BundleBaseResolver;
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

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MVC-layer test for {@link BundleController}'s authorization gate:
 * {@code TENANT_CREATE} — the same perm as {@code POST /api/v1/tenants},
 * so the wizard audience (platform-admin composite carries it) keeps
 * working while tenant end-user tokens are rejected.
 */
@SpringBootTest(
    classes = BundleControllerWebMvcTest.TestApp.class,
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
class BundleControllerWebMvcTest {

    @MockitoBean BundleBaseResolver bases;
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
    void bases_returns_401_without_auth() throws Exception {
        mvc.perform(get("/api/v1/bundle/bases"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void bases_returns_403_for_tenant_user_without_tenant_create() throws Exception {
        when(perms.has("TENANT_CREATE")).thenReturn(false);

        mvc.perform(get("/api/v1/bundle/bases").with(jwt()))
            .andExpect(status().isForbidden());
    }

    @Test
    void bases_returns_200_for_tenant_create_holder() throws Exception {
        when(perms.has("TENANT_CREATE")).thenReturn(true);
        when(bases.kcBase()).thenReturn("https://kc.example.com");
        when(bases.adminBase()).thenReturn("https://admin.example.com");
        when(bases.authMgrInClusterBase()).thenReturn("http://auth-manager.svc:8080");
        when(bases.authMgrPublicBase()).thenReturn("https://auth.example.com");

        mvc.perform(get("/api/v1/bundle/bases").with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.kcBase").value("https://kc.example.com"))
            .andExpect(jsonPath("$.adminBase").value("https://admin.example.com"));
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @ComponentScan(
        basePackages = "io.mcpmesh.auth.manager.api",
        useDefaultFilters = false,
        includeFilters = @ComponentScan.Filter(
            type = FilterType.ASSIGNABLE_TYPE,
            classes = {BundleController.class, GlobalExceptionHandler.class}
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
