package io.mcpmesh.auth.manager.theme;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.service.TenantService;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link ThemeService} — focused on the starter-zip assembly
 * path, which is pure-classpath and doesn't need any collaborator behaviour.
 */
class ThemeServiceTest {

    private final ThemeService service = new ThemeService(
        mock(TenantService.class),
        mock(ThemeValidator.class),
        mock(ThemeStorage.class),
        mock(ThemeApplier.class),
        mock(AuditService.class)
    );

    @Test
    void starterZip_containsAllExpectedEntries() throws Exception {
        byte[] zip = service.starterZip("anyslug");

        Set<String> names = readEntryNames(zip);

        assertThat(names).containsExactlyInAnyOrder(
            "login/theme.properties",
            "login/resources/css/custom.css",
            "login/resources/img/logo.svg",
            "login/messages/messages_en.properties",
            "account/theme.properties",
            "account/resources/css/custom.css",
            "account/resources/img/logo.svg",
            "email/theme.properties",
            "email/messages/messages_en.properties"
        );
        // 9 = 7 (prior login/account set) + 2 (new email/* additions).
        assertThat(names).hasSize(9);
    }

    @Test
    void starterZip_validatesCleanly() {
        // The generated zip should pass the production validator (PF v5
        // selectors + relative-only url() + sanitized SVGs).
        ThemeValidator realValidator = new ThemeValidator();
        byte[] zip = service.starterZip("anyslug");

        ValidationResult r = realValidator.validateZip(zip);

        assertThat(r.isValid())
            .as("starter zip should pass validation; errors: %s", r.errors())
            .isTrue();
    }

    private static Set<String> readEntryNames(byte[] zip) throws Exception {
        Set<String> names = new LinkedHashSet<>();
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                names.add(e.getName());
            }
        }
        return names;
    }
}
