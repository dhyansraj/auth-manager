package io.mcpmesh.auth.manager.email.templates;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Round-trips upsert/get/list/delete against stubbed repositories and asserts
 * the {@link EmailTemplateService#resolve} override + classpath-default
 * semantics. The repos are mocked but back onto in-memory maps so the
 * upsert→get→delete sequence behaves like a real store.
 */
class EmailTemplateServiceTest {

    private static final UUID TENANT_ID = UUID.fromString("00000000-0000-0000-0000-0000000000aa");

    private final Map<String, EmailTemplate> templates = new HashMap<>();
    private final List<EmailTemplateAsset> assets = new ArrayList<>();

    private EmailTemplateService service;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        templates.clear();
        assets.clear();

        EmailTemplateRepository templateRepo = mock(EmailTemplateRepository.class);
        EmailTemplateAssetRepository assetRepo = mock(EmailTemplateAssetRepository.class);
        AuditService audit = mock(AuditService.class);

        when(templateRepo.findByTenantIdAndTypeKey(any(), anyString()))
            .thenAnswer(i -> Optional.ofNullable(templates.get(key(i.getArgument(0), i.getArgument(1)))));
        when(templateRepo.saveAndFlush(any())).thenAnswer(i -> {
            EmailTemplate t = i.getArgument(0);
            templates.put(key(t.getTenantId(), t.getTypeKey()), t);
            return t;
        });
        when(templateRepo.findByTenantIdOrderByTypeKeyAsc(any())).thenAnswer(i -> {
            UUID t = i.getArgument(0);
            List<EmailTemplate> out = new ArrayList<>();
            for (EmailTemplate e : templates.values()) {
                if (e.getTenantId().equals(t)) out.add(e);
            }
            out.sort((a, b) -> a.getTypeKey().compareTo(b.getTypeKey()));
            return out;
        });
        doAnswer(i -> {
            templates.remove(key(i.getArgument(0), i.getArgument(1)));
            return null;
        }).when(templateRepo).deleteByTenantIdAndTypeKey(any(), anyString());

        when(assetRepo.findByTenantIdAndTypeKeyOrderByNameAsc(any(), anyString())).thenAnswer(i -> {
            UUID t = i.getArgument(0);
            String k = i.getArgument(1);
            List<EmailTemplateAsset> out = new ArrayList<>();
            for (EmailTemplateAsset a : assets) {
                if (a.getTenantId().equals(t) && a.getTypeKey().equals(k)) out.add(a);
            }
            out.sort((a, b) -> a.getName().compareTo(b.getName()));
            return out;
        });
        when(assetRepo.save(any())).thenAnswer(i -> {
            EmailTemplateAsset a = i.getArgument(0);
            assets.add(a);
            return a;
        });
        doAnswer(i -> {
            UUID t = i.getArgument(0);
            String k = i.getArgument(1);
            assets.removeIf(a -> a.getTenantId().equals(t) && a.getTypeKey().equals(k));
            return null;
        }).when(assetRepo).deleteByTenantIdAndTypeKey(any(), anyString());

        service = new EmailTemplateService(templateRepo, assetRepo, audit);
        tenant = mock(Tenant.class);
        when(tenant.getId()).thenReturn(TENANT_ID);
    }

    private static String key(UUID t, String k) { return t + "|" + k; }

    @Test
    void upsertGetListDelete_roundTrip() {
        byte[] png = {(byte) 0x89, 0x50, 0x4E, 0x47};
        service.upsert(TENANT_ID, "welcome", "<p>Hi {{tenantDisplayName}}</p>",
            "Welcome {{tenantDisplayName}}",
            List.of(new TemplateAsset("logo", "image/png", png)), "admin");

        Optional<EmailTemplate> got = service.get(TENANT_ID, "welcome");
        assertThat(got).isPresent();
        assertThat(got.get().getHtmlTemplate()).contains("{{tenantDisplayName}}");
        assertThat(got.get().getSubjectTemplate()).isEqualTo("Welcome {{tenantDisplayName}}");
        assertThat(service.assets(TENANT_ID, "welcome")).hasSize(1);
        assertThat(service.hasAssets(TENANT_ID, "welcome")).isTrue();
        assertThat(service.list(TENANT_ID)).hasSize(1);

        // Upsert again replaces body + asset set wholesale.
        service.upsert(TENANT_ID, "welcome", "<p>Updated</p>", null, List.of(), "admin");
        assertThat(service.get(TENANT_ID, "welcome")).get()
            .extracting(EmailTemplate::getHtmlTemplate).isEqualTo("<p>Updated</p>");
        assertThat(service.assets(TENANT_ID, "welcome")).isEmpty();

        assertThat(service.delete(TENANT_ID, "welcome", "admin")).isTrue();
        assertThat(service.get(TENANT_ID, "welcome")).isEmpty();
        assertThat(service.delete(TENANT_ID, "welcome", "admin")).isFalse();
    }

    @Test
    void resolve_returnsTenantOverride_whenPresent() {
        service.upsert(TENANT_ID, "invitation", "<p>Custom {{tenantDisplayName}}</p>",
            "Custom subject", List.of(), "admin");

        Optional<ResolvedTemplate> r = service.resolve(tenant, "invitation");
        assertThat(r).isPresent();
        assertThat(r.get().fromTenantOverride()).isTrue();
        assertThat(r.get().htmlTemplate()).contains("Custom");
        assertThat(r.get().subjectTemplate()).isEqualTo("Custom subject");
    }

    @Test
    void resolve_fallsBackToClasspathDefault_forInvitationOnly() {
        Optional<ResolvedTemplate> inv = service.resolve(tenant, "invitation");
        assertThat(inv).isPresent();
        assertThat(inv.get().fromTenantOverride()).isFalse();
        assertThat(inv.get().htmlTemplate()).contains("{{tenantDisplayName}}");
        assertThat(inv.get().assets()).isEmpty();
        // No password language in the default invitation.
        assertThat(inv.get().htmlTemplate().toLowerCase()).doesNotContain("password");

        // Any other unknown key resolves to empty.
        assertThat(service.resolve(tenant, "promotion")).isEmpty();
    }

    @Test
    void requireValidTypeKey_rejectsBadSlugs() {
        assertThatThrownBy(() -> EmailTemplateService.requireValidTypeKey("Bad_Key"))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> EmailTemplateService.requireValidTypeKey(""))
            .isInstanceOf(IllegalArgumentException.class);
        assertThat(EmailTemplateService.requireValidTypeKey("welcome-2")).isEqualTo("welcome-2");
    }
}
