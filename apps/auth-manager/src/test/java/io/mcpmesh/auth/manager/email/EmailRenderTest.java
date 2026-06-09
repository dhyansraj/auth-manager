package io.mcpmesh.auth.manager.email;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.email.templates.EmailTemplateService;
import io.mcpmesh.auth.manager.email.templates.ResolvedTemplate;
import io.mcpmesh.auth.manager.email.templates.TemplateAsset;
import io.mcpmesh.auth.manager.service.TenantService;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Renders a stored template + asset through the {@link TransactionalEmailService}
 * pipeline: Mustache vars expand, a {@code <style>} block is inlined onto
 * matching elements, and an {@code {{asset:name}}} reference becomes a
 * {@code cid:} reference backed by an inline MIME part.
 */
class EmailRenderTest {

    private Tenant tenant;

    @BeforeEach
    void setUp() {
        tenant = mock(Tenant.class);
        when(tenant.getSlug()).thenReturn("acme");
        when(tenant.getDisplayName()).thenReturn("Acme Inc");
        when(tenant.getEmailFromAddress()).thenReturn(null);
        when(tenant.getEmailFromDisplayName()).thenReturn(null);
    }

    private String renderToMime(ResolvedTemplate tpl, Map<String, Object> model) throws Exception {
        // Intercept the MimeMessage by overriding send via a capturing sender.
        final MimeMessage[] captured = new MimeMessage[1];
        JavaMailSenderImpl capturing = new JavaMailSenderImpl() {
            @Override public void send(MimeMessage mimeMessage) {
                captured[0] = mimeMessage;
            }
        };
        TransactionalEmailService s = new TransactionalEmailService(
            capturing, mockSmtp(), mock(TenantService.class), passthrough(tpl), new CssInliner());
        s.send(tenant, tpl.typeKey(), "to@example.com", "Subj", model);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        captured[0].writeTo(out);
        return out.toString("UTF-8");
    }

    private SmtpProperties mockSmtp() {
        SmtpProperties smtp = mock(SmtpProperties.class);
        when(smtp.getFromAddress()).thenReturn("noreply@platform.example");
        return smtp;
    }

    private EmailTemplateService passthrough(ResolvedTemplate tpl) {
        EmailTemplateService templates = mock(EmailTemplateService.class);
        when(templates.resolve(tenant, tpl.typeKey()))
            .thenReturn(java.util.Optional.of(tpl));
        return templates;
    }

    @Test
    void rendersMustache_inlinesStyleBlock_andEmitsCidForAsset() throws Exception {
        String html = """
            <html><head><style>.cta { color: #ffffff; background-color: #4f46e5; }</style></head>
            <body>
              <h1>{{tenantDisplayName}}</h1>
              <img src="cid:logo" alt="logo">
              <a class="cta" href="{{ctaUrl}}">Go</a>
            </body></html>
            """;
        byte[] png = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
        ResolvedTemplate tpl = new ResolvedTemplate(
            "welcome", html, "Hi {{tenantDisplayName}}",
            List.of(new TemplateAsset("logo", "image/png", png)), true);

        Map<String, Object> model = new LinkedHashMap<>();
        model.put("tenantDisplayName", "Acme Inc");
        model.put("ctaUrl", "https://acme.example/start");

        String mime = renderToMime(tpl, model);

        // Mustache vars expanded.
        assertThat(mime).contains("Acme Inc");
        assertThat(mime).contains("https://acme.example/start");
        // <style> rule inlined onto the .cta anchor.
        assertThat(mime).contains("background-color: #4f46e5");
        // The asset reference became a cid: reference + an inline part exists.
        assertThat(mime).contains("cid:logo@auth-manager");
        assertThat(mime.replace("\r\n", "\n").replace("\n", "")).contains("logo@auth-manager");
    }

    @Test
    void inviterModel_noAssets_stillSendsAsSimpleHtml() throws Exception {
        ResolvedTemplate tpl = new ResolvedTemplate(
            "welcome", "<p>Hi {{tenantDisplayName}}</p>", null, List.of(), false);
        Map<String, Object> model = new LinkedHashMap<>();
        model.put("tenantDisplayName", "Acme Inc");
        String mime = renderToMime(tpl, model);
        assertThat(mime).contains("Hi Acme Inc");
        assertThat(mime).doesNotContain("cid:");
    }
}
