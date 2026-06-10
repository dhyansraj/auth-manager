package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.domain.audit.AuditEvent;
import io.mcpmesh.auth.manager.persistence.AuditEventRepository;
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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MVC-layer test for {@link AuditController}'s authorization gate:
 * platform-admin OR {@code AUDIT_VIEW}. A tenant end-user token without
 * perms must be rejected (the multi-realm resolver authenticates ANY
 * realm's JWT, so {@code isAuthenticated()} alone is not a gate).
 *
 * <p>Same stripped-down boot context idiom as
 * {@link TenantControllerWebMvcTest}.
 */
@SpringBootTest(
    classes = AuditControllerWebMvcTest.TestApp.class,
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
class AuditControllerWebMvcTest {

    private static final UUID APP1_ID = UUID.randomUUID();

    @MockitoBean AuditEventRepository auditRepo;
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

    @Test
    void list_returns_401_without_auth() throws Exception {
        mvc.perform(get("/api/v1/audit"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void list_returns_403_for_tenant_user_without_audit_view() throws Exception {
        when(tenantSecurity.isPlatformAdmin()).thenReturn(false);
        when(perms.has("AUDIT_VIEW")).thenReturn(false);

        mvc.perform(get("/api/v1/audit").with(jwt()))
            .andExpect(status().isForbidden());
    }

    @Test
    void list_returns_all_events_for_platform_admin() throws Exception {
        when(tenantSecurity.isPlatformAdmin()).thenReturn(true);
        when(auditRepo.findAllByOrderByOccurredAtDesc(any(Pageable.class)))
            .thenReturn(Page.<AuditEvent>empty(PageRequest.of(0, 50)));

        mvc.perform(get("/api/v1/audit").with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.items.length()").value(0));

        verify(auditRepo).findAllByOrderByOccurredAtDesc(any(Pageable.class));
        verify(auditRepo, never()).findByTenantIdOrderByOccurredAtDesc(any(), any());
    }

    @Test
    void list_scopes_to_own_tenant_for_audit_view_holder() throws Exception {
        when(tenantSecurity.isPlatformAdmin()).thenReturn(false);
        when(perms.has("AUDIT_VIEW")).thenReturn(true);
        when(tenantSecurity.currentTenantId()).thenReturn(Optional.of(APP1_ID));
        when(auditRepo.findByTenantIdOrderByOccurredAtDesc(eq(APP1_ID), any(Pageable.class)))
            .thenReturn(Page.<AuditEvent>empty(PageRequest.of(0, 50)));

        mvc.perform(get("/api/v1/audit").with(jwt()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.items.length()").value(0));

        verify(auditRepo).findByTenantIdOrderByOccurredAtDesc(eq(APP1_ID), any(Pageable.class));
        verify(auditRepo, never()).findAllByOrderByOccurredAtDesc(any());
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @ComponentScan(
        basePackages = "io.mcpmesh.auth.manager.api",
        useDefaultFilters = false,
        includeFilters = @ComponentScan.Filter(
            type = FilterType.ASSIGNABLE_TYPE,
            classes = {AuditController.class, GlobalExceptionHandler.class}
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
