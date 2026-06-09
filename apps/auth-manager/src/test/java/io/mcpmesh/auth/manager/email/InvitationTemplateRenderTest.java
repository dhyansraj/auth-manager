package io.mcpmesh.auth.manager.email;

import com.samskivert.mustache.Mustache;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Renders the actual {@link EmailType#INVITATION} template resource and asserts
 * the output contains the tenant name + invite URL and carries NO
 * password-language (this email replaces KC's UPDATE_PASSWORD invite).
 */
class InvitationTemplateRenderTest {

    private String render(Map<String, Object> model) throws Exception {
        ClassPathResource res = new ClassPathResource(EmailType.INVITATION.getTemplateResource());
        try (Reader reader = new InputStreamReader(res.getInputStream(), StandardCharsets.UTF_8)) {
            return Mustache.compiler().compile(reader).execute(model);
        }
    }

    @Test
    void rendersTenantNameAndInviteUrl_withoutPasswordLanguage() throws Exception {
        Map<String, Object> model = new LinkedHashMap<>();
        model.put("tenantDisplayName", "WiseFolio");
        model.put("inviteUrl", "https://app.wisefolio.example/");
        model.put("recipientEmail", "newuser@example.com");

        String html = render(model);

        assertThat(html).contains("WiseFolio");
        assertThat(html).contains("https://app.wisefolio.example/");
        assertThat(html).contains("newuser@example.com");

        String lower = html.toLowerCase();
        assertThat(lower).doesNotContain("password");
        assertThat(lower).doesNotContain("reset");
    }

    @Test
    void optionalInviterName_rendersWhenPresent_absentWhenMissing() throws Exception {
        Map<String, Object> withInviter = new LinkedHashMap<>();
        withInviter.put("tenantDisplayName", "Acme");
        withInviter.put("inviteUrl", "https://acme.example/");
        withInviter.put("recipientEmail", "u@example.com");
        withInviter.put("inviterName", "Dana Admin");
        assertThat(render(withInviter)).contains("Dana Admin");

        Map<String, Object> withoutInviter = new LinkedHashMap<>();
        withoutInviter.put("tenantDisplayName", "Acme");
        withoutInviter.put("inviteUrl", "https://acme.example/");
        withoutInviter.put("recipientEmail", "u@example.com");
        assertThat(render(withoutInviter)).doesNotContain("Invited by");
    }
}
