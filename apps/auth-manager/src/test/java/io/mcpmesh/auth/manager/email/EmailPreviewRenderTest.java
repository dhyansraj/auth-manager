package io.mcpmesh.auth.manager.email;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.email.templates.EmailTemplateService;
import io.mcpmesh.auth.manager.email.templates.ResolvedTemplate;
import io.mcpmesh.auth.manager.email.templates.TemplateAsset;
import io.mcpmesh.auth.manager.service.TenantService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Exercises {@link TransactionalEmailService#renderPreview}: leftover
 * {@code {{var}}} tags become {@code [var]} placeholders, the {@code <style>}
 * block is inlined, and a {@code cid:}/asset reference is rewritten to an inline
 * {@code data:} URI from the stored asset bytes (so the preview renders
 * standalone with no mail client).
 */
class EmailPreviewRenderTest {

    private Tenant tenant;
    private TransactionalEmailService service;
    private EmailTemplateService templates;

    @BeforeEach
    void setUp() {
        tenant = mock(Tenant.class);
        when(tenant.getSlug()).thenReturn("acme");
        templates = mock(EmailTemplateService.class);
        SmtpProperties smtp = mock(SmtpProperties.class);
        service = new TransactionalEmailService(
            new JavaMailSenderImpl(), smtp, mock(TenantService.class), templates, new CssInliner());
    }

    @Test
    void preview_substitutesVars_inlinesCss_andInlinesAssetAsDataUri() {
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
            "promo", html, "Subject {{tenantDisplayName}}",
            List.of(new TemplateAsset("logo", "image/png", png)), true);
        when(templates.resolve(tenant, "promo")).thenReturn(Optional.of(tpl));

        Optional<String> out = service.renderPreview(tenant, "promo");
        assertThat(out).isPresent();
        String rendered = out.get();

        // Leftover Mustache vars surfaced as visible placeholders.
        assertThat(rendered).contains("[tenantDisplayName]");
        assertThat(rendered).contains("[ctaUrl]");
        assertThat(rendered).doesNotContain("{{");

        // CSS inlined onto the .cta anchor.
        assertThat(rendered).contains("background-color: #4f46e5");

        // Asset reference rewritten to a standalone data: URI (no cid: left).
        String expectedDataUri = "data:image/png;base64,"
            + Base64.getEncoder().encodeToString(png);
        assertThat(rendered).contains(expectedDataUri);
        assertThat(rendered).doesNotContain("cid:logo");
    }

    @Test
    void preview_returnsEmpty_whenNoTemplateResolves() {
        when(templates.resolve(tenant, "missing")).thenReturn(Optional.empty());
        assertThat(service.renderPreview(tenant, "missing")).isEmpty();
    }
}
