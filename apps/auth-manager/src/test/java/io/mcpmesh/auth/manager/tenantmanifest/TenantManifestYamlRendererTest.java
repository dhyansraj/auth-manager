package io.mcpmesh.auth.manager.tenantmanifest;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TenantManifestYamlRenderer}. Focus is the starter
 * output (empty manifest) and the env-awareness of the curl apply URL — a DEV
 * adminBase must NOT leak the PROD host.
 */
class TenantManifestYamlRendererTest {

    private static final UUID TENANT_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");

    private Tenant devTenant() {
        Tenant t = mock(Tenant.class);
        when(t.getId()).thenReturn(TENANT_ID);
        when(t.getDisplayName()).thenReturn("Dev Tenant");
        return t;
    }

    @Test
    void starter_usesPassedAdminBase_andHasNoProdHost() throws Exception {
        String adminBase = "https://auth-dev.mcp-mesh.io/admin";
        String out = TenantManifestYamlRenderer.render(
            new ObjectMapper(), devTenant(), null, adminBase);

        assertThat(out)
            .contains(adminBase + "/api/v1/tenants/" + TENANT_ID
                + "/manifest:apply?applyRoles=true");
        assertThat(out).doesNotContain("auth.mcp-mesh.io");
    }
}
