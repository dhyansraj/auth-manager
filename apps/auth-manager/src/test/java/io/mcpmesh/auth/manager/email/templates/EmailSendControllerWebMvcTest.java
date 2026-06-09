package io.mcpmesh.auth.manager.email.templates;

import io.mcpmesh.auth.manager.api.GlobalExceptionHandler;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.email.TransactionalEmailService;
import io.mcpmesh.auth.manager.security.Permissions;
import io.mcpmesh.auth.manager.security.TenantSecurity;
import io.mcpmesh.auth.manager.service.TenantService;
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

import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * WebMvc slice for the app-facing send API. Verifies the {@code EMAIL_SEND}
 * gate, the stored-only resolution (404 when no override), the reserved-key
 * rejection, and {@code @Email} body validation, all with the service layer
 * mocked.
 */
@SpringBootTest(
    classes = EmailSendControllerWebMvcTest.TestApp.class,
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
class EmailSendControllerWebMvcTest {

    private static final UUID TENANT_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");
    private static final String BASE = "/api/v1/tenants/" + TENANT_ID + "/emails";

    @MockitoBean TenantService tenants;
    @MockitoBean EmailTemplateService templates;
    @MockitoBean TransactionalEmailService emailService;
    @MockitoBean io.mcpmesh.auth.manager.audit.AuditService audit;
    @MockitoBean EmailRateLimiter rateLimiter;
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

    private void allowSend() {
        when(perms.hasOnTenantId(eq(TENANT_ID), eq("EMAIL_SEND"))).thenReturn(true);
    }

    private void stubTenant() {
        Tenant tenant = org.mockito.Mockito.mock(Tenant.class);
        when(tenant.getId()).thenReturn(TENANT_ID);
        when(tenants.get(eq(TENANT_ID))).thenReturn(tenant);
    }

    @Test
    void send_returns_401_withoutAuth() throws Exception {
        mvc.perform(post(BASE + "/promo")
                .contentType("application/json")
                .content("{\"to\":\"x@y.com\"}"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void send_returns_403_withoutPermission() throws Exception {
        when(perms.hasOnTenantId(eq(TENANT_ID), eq("EMAIL_SEND"))).thenReturn(false);
        mvc.perform(post(BASE + "/promo").with(jwt())
                .contentType("application/json")
                .content("{\"to\":\"x@y.com\"}"))
            .andExpect(status().isForbidden());
    }

    @Test
    void send_returns_202_andSends_whenTemplateStored() throws Exception {
        allowSend();
        stubTenant();
        EmailTemplate tpl = new EmailTemplate(TENANT_ID, "promo", "<p>Hi</p>", "Promo subject");
        when(templates.get(eq(TENANT_ID), eq("promo"))).thenReturn(Optional.of(tpl));

        mvc.perform(post(BASE + "/promo").with(jwt())
                .contentType("application/json")
                .content("{\"to\":\"buyer@example.com\",\"model\":{\"name\":\"Sam\"}}"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.sent").value(true));

        verify(emailService).send(any(Tenant.class), eq("promo"),
            eq("buyer@example.com"), eq("Promo subject"), any());
        verify(audit).recordSuccess(anyString(), any(), eq(TENANT_ID),
            eq("email.send"), eq("email_template"), eq("promo"), any(), any());
    }

    @Test
    void send_returns_429_withRetryAfter_whenRateLimited() throws Exception {
        allowSend();
        org.mockito.Mockito.doThrow(new EmailRateLimitException(42,
                "Per-minute email limit exceeded"))
            .when(rateLimiter).checkAndIncrement(eq(TENANT_ID));

        mvc.perform(post(BASE + "/promo").with(jwt())
                .contentType("application/json")
                .content("{\"to\":\"buyer@example.com\"}"))
            .andExpect(status().isTooManyRequests())
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                .header().string("Retry-After", "42"))
            .andExpect(jsonPath("$.error").value("email_rate_limited"))
            .andExpect(jsonPath("$.retryAfterSeconds").value(42));

        // Rejected before any resolve/render/send work.
        verify(templates, never()).get(any(), anyString());
        verify(emailService, never()).send(any(), anyString(), anyString(), any(), any());
    }

    @Test
    void send_returns_404_whenNoStoredTemplate() throws Exception {
        allowSend();
        stubTenant();
        when(templates.get(eq(TENANT_ID), eq("unknown-x"))).thenReturn(Optional.empty());

        mvc.perform(post(BASE + "/unknown-x").with(jwt())
                .contentType("application/json")
                .content("{\"to\":\"x@example.com\"}"))
            .andExpect(status().isNotFound());

        verify(emailService, never()).send(any(), anyString(), anyString(), any(), any());
    }

    @Test
    void send_returns_409_forReservedInvitationKey() throws Exception {
        allowSend();
        mvc.perform(post(BASE + "/invitation").with(jwt())
                .contentType("application/json")
                .content("{\"to\":\"x@example.com\"}"))
            .andExpect(status().isConflict());

        verify(emailService, never()).send(any(), anyString(), anyString(), any(), any());
    }

    @Test
    void send_returns_400_forInvalidTo() throws Exception {
        allowSend();
        mvc.perform(post(BASE + "/promo").with(jwt())
                .contentType("application/json")
                .content("{\"to\":\"not-an-email\"}"))
            .andExpect(status().isBadRequest());

        verify(emailService, never()).send(any(), anyString(), anyString(), any(), any());
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @ComponentScan(
        basePackages = {
            "io.mcpmesh.auth.manager.email.templates",
            "io.mcpmesh.auth.manager.api"
        },
        useDefaultFilters = false,
        includeFilters = @ComponentScan.Filter(
            type = FilterType.ASSIGNABLE_TYPE,
            classes = {EmailSendController.class, GlobalExceptionHandler.class}
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
