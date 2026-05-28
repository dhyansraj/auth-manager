package io.mcpmesh.auth.manager.tenantmanifest;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;

import java.time.Instant;
import java.util.List;

/**
 * Renders a {@link TenantManifest} as YAML for operator download.
 *
 * <p>Two flavors:
 * <ul>
 *   <li><strong>Live state</strong> — the tenant has at least one permission OR
 *       at least one role. Output is the deterministic YAML serialization with
 *       a single-line comment header noting the download time. Suitable for
 *       editing + re-applying.</li>
 *   <li><strong>Starter</strong> — the tenant has nothing yet. Output is a
 *       commented skeleton showing the expected shape with the tenant's id +
 *       a backend clientId placeholder pre-filled. Apply-as-is is a no-op,
 *       which is the intended behavior for an operator who just wants to see
 *       the structure.</li>
 * </ul>
 *
 * <p>The starter intentionally omits the {@code meta:} block so re-uploading
 * it doesn't propagate stale generation timestamps. Apply tolerates the
 * omission ({@code meta} is informational).
 */
public final class TenantManifestYamlRenderer {

    private TenantManifestYamlRenderer() {}

    public static String render(ObjectMapper yamlMapper,
                                Tenant tenant,
                                TenantManifest manifest) throws Exception {
        return render(yamlMapper, tenant, manifest, null);
    }

    /**
     * @param firstBackendClientId optional — when non-null, used to pre-fill
     *                             the example permission's {@code client:}
     *                             line in the starter. Pass null to fall back
     *                             to the {@code <your-backend-client-id>}
     *                             placeholder.
     */
    public static String render(ObjectMapper yamlMapper,
                                Tenant tenant,
                                TenantManifest manifest,
                                String firstBackendClientId) throws Exception {
        boolean empty = isEmpty(manifest);
        if (empty) {
            return renderStarter(tenant, firstBackendClientId);
        }
        String header = "# " + tenant.getDisplayName()
            + " — current permission catalog + role bundles"
            + " (downloaded " + Instant.now() + ")\n";
        return header + yamlMapper.writeValueAsString(manifest);
    }

    private static boolean isEmpty(TenantManifest manifest) {
        if (manifest == null) return true;
        List<TenantManifest.PermissionEntry> perms = manifest.permissions();
        List<TenantManifest.RoleEntry> roles = manifest.roles();
        return (perms == null || perms.isEmpty()) && (roles == null || roles.isEmpty());
    }

    private static String renderStarter(Tenant tenant, String firstBackendClientId) {
        String clientPlaceholder = (firstBackendClientId == null || firstBackendClientId.isBlank())
            ? "<your-backend-client-id>"
            : firstBackendClientId;
        return ("""
            # {{tenantName}} — permission catalog + role bundles
            #
            # Apply via the auth-manager UI (Permissions tab → Upload manifest) OR
            # the REST API:
            #   curl -X POST \\
            #     -H "Authorization: Bearer $TOKEN" \\
            #     -H "Content-Type: application/x-yaml" \\
            #     "https://auth.mcp-mesh.io/admin/api/v1/tenants/{{tenantId}}/manifest:apply?applyRoles=true" \\
            #     --data-binary @tenant-manifest.yaml
            #
            # Or download the current state any time from the Permissions tab → Download manifest.

            permissions:
              # Define your app's atomic permissions here. The `client` field references
              # one of your CONFIDENTIAL_BACKEND or SERVICE_ACCOUNT_ONLY apps.
              # - id: DASHBOARD_VIEW
              #   description: View the dashboard
              #   client: {{clientPlaceholder}}

            roles:
              # Define role bundles here. A role is a named bundle of permissions.
              # Code references the role's PERMISSIONS via @RequirePermission(...),
              # not the role name. Use roles as the unit of UI/operator assignment.
              # - name: admin
              #   description: Org admin
              #   permissions: [DASHBOARD_VIEW]

            identityProviders:
              # - id: google
              #   enabled: true
              # - id: github
              #   enabled: true

            defaultRoles:
              # Roles automatically granted to every user in this tenant's realm.
              # - user
            """)
            .replace("{{tenantName}}", tenant.getDisplayName())
            .replace("{{tenantId}}", tenant.getId().toString())
            .replace("{{clientPlaceholder}}", clientPlaceholder);
    }
}
