package io.mcpmesh.auth.manager.service;

import io.mcpmesh.auth.manager.domain.app.App;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.IdentityProvidersBootstrap;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.persistence.AppRepository;
import io.mcpmesh.auth.manager.routing.RoutingConfigService;
import io.mcpmesh.auth.manager.routing.model.RoutingConfig;
import io.mcpmesh.auth.manager.tenantmanifest.TenantManifest;
import io.mcpmesh.auth.manager.tenantmanifest.TenantManifestService;
import io.mcpmesh.auth.manager.tenantmanifest.TenantManifestYamlRenderer;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@Service
public class OnboardingBundleService {

    private static final Logger log = LoggerFactory.getLogger(OnboardingBundleService.class);

    private static final String KC_BASE = "https://auth.mcp-mesh.io/auth";
    private static final String AUTH_MGR_BASE =
        "http://auth-platform-auth-manager.auth-platform.svc.cluster.local:8080";
    private static final String ADMIN_BASE = "https://auth.mcp-mesh.io/admin";

    private final TenantService tenants;
    private final AppRepository appRepo;
    private final Keycloak admin;
    private final KeycloakAdminService keycloak;
    private final IdentityProvidersBootstrap idp;
    private final RoutingConfigService routing;
    private final TenantDatabaseService databaseService;
    private final TenantManifestService manifestService;
    private final ObjectMapper manifestYamlMapper;

    public OnboardingBundleService(TenantService tenants,
                                   AppRepository appRepo,
                                   Keycloak admin,
                                   KeycloakAdminService keycloak,
                                   IdentityProvidersBootstrap idp,
                                   RoutingConfigService routing,
                                   TenantDatabaseService databaseService,
                                   TenantManifestService manifestService) {
        this.tenants = tenants;
        this.appRepo = appRepo;
        this.admin = admin;
        this.keycloak = keycloak;
        this.idp = idp;
        this.routing = routing;
        this.databaseService = databaseService;
        this.manifestService = manifestService;
        YAMLFactory yf = new YAMLFactory()
            .disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER)
            .enable(YAMLGenerator.Feature.MINIMIZE_QUOTES)
            .enable(YAMLGenerator.Feature.INDENT_ARRAYS_WITH_INDICATOR);
        this.manifestYamlMapper = new ObjectMapper(yf)
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    public byte[] build(UUID tenantId) {
        Tenant tenant = tenants.get(tenantId);
        String slug = tenant.getSlug();
        String realmName = tenant.getRealmName() == null ? "t-" + slug : tenant.getRealmName();
        String issuer = KC_BASE + "/realms/" + realmName;

        List<App> allApps = appRepo.findByTenantIdOrderByCreatedAtDesc(tenantId);
        List<AppInfo> userApps = new ArrayList<>();
        for (App a : allApps) {
            if ("usermanagement".equals(a.getSlug())) continue;
            userApps.add(new AppInfo(a, detectProfile(realmName, a.getClientId())));
        }

        boolean bffMode = isBffMode(slug);
        Set<String> enabledIdps = idp.listEnabledProviders(realmName);
        boolean dbProvisioned = safeDbExists(slug);

        boolean anySpa = userApps.stream().anyMatch(a -> "SPA_PKCE".equals(a.profile));
        boolean anyBackend = userApps.stream().anyMatch(a -> "CONFIDENTIAL_BACKEND".equals(a.profile));
        boolean anyServiceAccount = userApps.stream().anyMatch(a -> "SERVICE_ACCOUNT_ONLY".equals(a.profile));
        boolean anyUiFacing = anySpa || anyBackend;

        // Compute the final file list up-front so the README can reference it.
        List<String> filesGenerated = new ArrayList<>();
        filesGenerated.add("README.md");
        filesGenerated.add(".env.example");
        filesGenerated.add("helm-values-snippet.yaml");
        filesGenerated.add("tenant-manifest.yaml");
        if (!enabledIdps.isEmpty()) filesGenerated.add("01-broker-urls.md");
        if (anyUiFacing) filesGenerated.add("02-frontend.md");
        if (anyBackend || anyServiceAccount) {
            filesGenerated.add("03-backend-java.md");
            filesGenerated.add("03-backend-python.md");
        }
        if (anyServiceAccount) filesGenerated.add("04-service-account.md");
        filesGenerated.add("05-theming-optional.md");
        filesGenerated.add("06-user-migration.md");
        filesGenerated.add("07-in-cluster-vs-public.md");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(baos)) {
            writeEntry(zip, "README.md", renderReadme(tenant, realmName, issuer, slug, userApps, bffMode,
                                                     anySpa, anyBackend, anyServiceAccount,
                                                     !enabledIdps.isEmpty(), filesGenerated));
            writeEntry(zip, ".env.example", renderEnv(tenant, issuer, slug, userApps, bffMode, dbProvisioned));
            writeEntry(zip, "helm-values-snippet.yaml", renderHelm(issuer, slug, userApps, bffMode));
            writeEntry(zip, "tenant-manifest.yaml", renderTenantManifest(tenant, userApps));
            if (!enabledIdps.isEmpty()) {
                writeEntry(zip, "01-broker-urls.md", renderBrokerUrls(realmName, enabledIdps));
            }
            if (anyUiFacing) {
                String frontend = bffMode ? renderFrontendBff() : renderFrontendDirect(userApps);
                writeEntry(zip, "02-frontend.md", frontend);
            }
            if (anyBackend || anyServiceAccount) {
                writeEntry(zip, "03-backend-java.md", renderBackendJava(tenant, realmName, slug, issuer, userApps, bffMode));
                writeEntry(zip, "03-backend-python.md", renderBackendPython(tenant, realmName, slug, issuer, userApps, bffMode));
            }
            if (anyServiceAccount) {
                writeEntry(zip, "04-service-account.md", renderServiceAccount(issuer, userApps));
            }
            writeEntry(zip, "05-theming-optional.md", renderTheming(slug));
            writeEntry(zip, "06-user-migration.md", renderMigration(realmName));
            writeEntry(zip, "07-in-cluster-vs-public.md", renderInClusterVsPublic(slug, realmName));
        } catch (IOException e) {
            throw new RuntimeException("Failed to build onboarding bundle zip", e);
        }
        return baos.toByteArray();
    }

    /**
     * Best-effort existence check for the tenant's managed Postgres DB
     * on the shared CNPG cluster. Failures here (CNPG unreachable, etc.)
     * degrade to "not provisioned" — better to leave the DATABASE_*
     * block out of the bundle than to fail the whole download.
     */
    private boolean safeDbExists(String slug) {
        try {
            return databaseService.existsFor(slug);
        } catch (Exception e) {
            log.debug("safeDbExists({}): CNPG lookup failed ({}), assuming not provisioned",
                slug, e.getMessage());
            return false;
        }
    }

    /**
     * BFF mode = platform-edge handles auth for this tenant. We detect this by
     * the presence of a non-empty routing config in Postgres (the same row
     * platform-edge reads via Redis): routes present => edge is forwarding
     * traffic => BFF mode. No routes / lookup failure => default to BFF
     * (it's the recommended path; the doc warnings around SPA clients still
     * apply, and a tenant who actually runs Direct OIDC will see an
     * empty-rules config too — we accept the false positive there).
     */
    private boolean isBffMode(String slug) {
        try {
            RoutingConfig cfg = routing.getForTenant(slug);
            return cfg != null && cfg.rules() != null && !cfg.rules().isEmpty();
        } catch (Exception e) {
            log.debug("isBffMode({}): routing lookup failed ({}), defaulting to BFF",
                slug, e.getMessage());
            return true;
        }
    }

    private static void writeEntry(ZipOutputStream zip, String name, String content) throws IOException {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(content.getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
    }

    /**
     * Maps KC client flags to one of the three wizard profiles. Best-effort —
     * missing client or KC errors degrade to CONFIDENTIAL_BACKEND (the safest
     * default for emitting backend client envs).
     */
    private String detectProfile(String realmName, String clientId) {
        try {
            var matches = admin.realm(realmName).clients().findByClientId(clientId);
            if (matches.isEmpty()) return "CONFIDENTIAL_BACKEND";
            ClientRepresentation c = matches.get(0);
            if (Boolean.TRUE.equals(c.isPublicClient())) return "SPA_PKCE";
            boolean standard = !Boolean.FALSE.equals(c.isStandardFlowEnabled());
            boolean sa = Boolean.TRUE.equals(c.isServiceAccountsEnabled());
            if (!standard && sa) return "SERVICE_ACCOUNT_ONLY";
            return "CONFIDENTIAL_BACKEND";
        } catch (Exception e) {
            log.warn("detectProfile({}, {}) failed: {} — defaulting to CONFIDENTIAL_BACKEND",
                realmName, clientId, e.getMessage());
            return "CONFIDENTIAL_BACKEND";
        }
    }

    private String firstBackendClientId(List<AppInfo> apps) {
        return apps.stream()
            .filter(a -> "CONFIDENTIAL_BACKEND".equals(a.profile))
            .findFirst()
            .map(a -> a.app.getClientId())
            .orElse("<your-backend-client-id>");
    }

    private static String envVarName(String clientId) {
        return clientId.toUpperCase(java.util.Locale.ROOT).replace('-', '_');
    }

    // ------------------------------------------------------------------ templates

    private String renderReadme(Tenant t, String realmName, String issuer, String slug,
                                List<AppInfo> apps, boolean bffMode,
                                boolean anySpa, boolean anyBackend, boolean anyServiceAccount,
                                boolean anyIdp, List<String> filesGenerated) {
        String appsList = apps.isEmpty()
            ? "_(no apps registered yet)_"
            : apps.stream()
                .map(a -> "- `" + a.app.getSlug() + "` (" + a.profile
                          + ") — client ID: `" + a.app.getClientId() + "`")
                .reduce((x, y) -> x + "\n" + y)
                .orElse("");

        String fileListBlock = filesGenerated.stream()
            .map(f -> "- `" + f + "`")
            .reduce((x, y) -> x + "\n" + y)
            .orElse("");

        String modeBadge = bffMode
            ? "Platform-edge BFF (recommended)"
            : "Direct OIDC (tenant-managed ingress)";
        String modeExplanation = bffMode
            ? """
              Browser traffic to your tenant flows through the platform-edge ingress, which
              handles login (`/_bff/login`), cookie sessions, and cookie→Bearer translation
              before forwarding to your backend. Your code only sees `Authorization: Bearer ...`
              on the backend; the browser only sees a cookie. You don't run your own OIDC
              client — the platform's per-realm `usermanagement` client does it for you."""
            : """
              No platform-edge routes are configured for this tenant — you're expected to
              run your own ingress and either (a) implement your own BFF that exchanges the
              OIDC code for tokens, or (b) use a pure-SPA flow where the browser holds the
              access token. The docs below assume (b); for (a) the React lib's session
              helpers are useful, but the BFF/cookie endpoints (`/_bff/login` etc.) are on
              your side, not ours.""";

        StringBuilder warnings = new StringBuilder();
        if (bffMode && anySpa) {
            for (AppInfo a : apps) {
                if ("SPA_PKCE".equals(a.profile)) {
                    warnings.append("- ⚠️  App `").append(a.app.getClientId())
                        .append("` is SPA_PKCE but you're in BFF mode — the SPA client is unused. ")
                        .append("The platform's `usermanagement` client handles login. ")
                        .append("Consider deleting this app via the Apps tab unless you also need ")
                        .append("direct browser-to-KC for some flow.\n");
                }
            }
        }
        for (AppInfo a : apps) {
            if (!"CONFIDENTIAL_BACKEND".equals(a.profile)) continue;
            if (!keycloak.hasUsermanagementAudienceFor(realmName, a.app.getClientId())) {
                warnings.append("- ⚠️  App `").append(a.app.getClientId())
                    .append("` — usermanagement is not configured to inject `aud:")
                    .append(a.app.getClientId())
                    .append("` into BFF-issued tokens. Bearer validation in your backend will reject these tokens. ")
                    .append("Re-create the app via the wizard (the new flow auto-configures this) ")
                    .append("OR retry via auth-manager UI → Apps → ").append(a.app.getClientId())
                    .append(" → \"Wire BFF audience\" (TODO: add this button).\n");
            }
        }
        String warningsBlock = warnings.length() == 0
            ? ""
            : "\n## Warnings\n\n" + warnings.toString().stripTrailing() + "\n";

        return ("""
            # {{tenantName}} — Auth Platform Onboarding

            This bundle has everything your team needs to integrate with the mcp-mesh
            auth platform. Work through it in order.

            ## Integration mode

            **{{modeBadge}}**

            {{modeExplanation}}

            ## What you got

            {{fileList}}

            ## Tenant info

            - Slug: `{{slug}}`
            - Realm: `{{realmName}}`
            - Issuer: `{{issuer}}`
            - Admin console: {{adminBase}}/tenants/{{slug}}

            ## Apps registered

            {{appsList}}
            {{warningsBlock}}
            ## Questions?

            Ping the platform team. The auth-manager UI at {{adminBase}} is the source of truth — your apps/permissions/branding all live there.
            """)
            .replace("{{tenantName}}", t.getDisplayName())
            .replace("{{slug}}", slug)
            .replace("{{realmName}}", realmName)
            .replace("{{issuer}}", issuer)
            .replace("{{adminBase}}", ADMIN_BASE)
            .replace("{{modeBadge}}", modeBadge)
            .replace("{{modeExplanation}}", modeExplanation)
            .replace("{{fileList}}", fileListBlock)
            .replace("{{appsList}}", appsList)
            .replace("{{warningsBlock}}", warningsBlock);
    }

    private String renderEnv(Tenant t, String issuer, String slug, List<AppInfo> apps,
                              boolean bffMode, boolean dbProvisioned) {
        String dbBlock = renderDbBlock(slug, dbProvisioned);
        if (bffMode) {
            String backendClientId = firstBackendClientId(apps);
            StringBuilder backendClientsBlock = new StringBuilder();
            List<AppInfo> backendApps = apps.stream()
                .filter(a -> "CONFIDENTIAL_BACKEND".equals(a.profile))
                .toList();
            if (!backendApps.isEmpty()) {
                backendClientsBlock.append("# Backend client credentials (for service-to-service calls, introspection, etc.)\n");
                backendClientsBlock.append("# Secret values: copy from auth-manager UI → Apps → <name> → Reveal\n");
                for (int i = 0; i < backendApps.size(); i++) {
                    String cid = backendApps.get(i).app.getClientId();
                    String cidUpper = envVarName(cid);
                    backendClientsBlock.append(cidUpper).append("_CLIENT_ID=").append(cid).append('\n');
                    backendClientsBlock.append(cidUpper).append("_CLIENT_SECRET=<paste from auth-manager UI>\n");
                    if (i < backendApps.size() - 1) {
                        backendClientsBlock.append('\n');
                    }
                }
            }
            StringBuilder saBlock = new StringBuilder();
            for (AppInfo a : apps) {
                if (!"SERVICE_ACCOUNT_ONLY".equals(a.profile)) continue;
                String cid = a.app.getClientId();
                String cidUpper = envVarName(cid);
                saBlock.append("# ").append(cid).append(" — m2m service account\n");
                saBlock.append(cidUpper).append("_CLIENT_ID=").append(cid).append('\n');
                saBlock.append(cidUpper).append("_CLIENT_SECRET=<paste from auth-manager UI → Apps → ")
                    .append(cid).append(" → Reveal>\n\n");
            }
            String sa = saBlock.length() == 0
                ? "# (no service-account clients registered)"
                : saBlock.toString().stripTrailing();
            String backendClients = backendClientsBlock.length() == 0
                ? ""
                : backendClientsBlock.toString().stripTrailing() + "\n\n";
            return ("""
                # Auth platform integration — {{tenantName}}
                # Mode: Platform-edge BFF
                # Generated {{timestamp}} from auth-manager onboarding bundle.

                # Backend services (validate Bearer tokens received from platform-edge)
                AUTH_LIB_ISSUER_URI={{issuer}}
                AUTH_LIB_CLIENT_ID={{clientId}}
                AUTH_LIB_PERMISSIONS_SOURCE=claims
                # Python lib only: comma-separated extra audiences if you serve multiple backends
                # AUTH_LIB_AUDIENCES=other-backend,another-one

                # Frontend (your React app) — NO client_id/secret needed.
                # All auth flows go through https://<your-host>/_bff/* endpoints which
                # platform-edge handles. fetch() with credentials: 'include' is all you need.

                {{backendClientsBlock}}# If your backend needs to call other services as itself (service account):
                {{serviceAccountBlock}}
                {{dbBlock}}
                """)
                .replace("{{tenantName}}", t.getDisplayName())
                .replace("{{timestamp}}", Instant.now().toString())
                .replace("{{issuer}}", issuer)
                .replace("{{clientId}}", backendClientId)
                .replace("{{backendClientsBlock}}", backendClients)
                .replace("{{serviceAccountBlock}}", sa)
                .replace("{{dbBlock}}", dbBlock)
                .stripTrailing() + "\n";
        }

        // Direct OIDC mode
        StringBuilder spaBlock = new StringBuilder();
        for (AppInfo a : apps) {
            if (!"SPA_PKCE".equals(a.profile)) continue;
            spaBlock.append("# SPA client: ").append(a.app.getClientId()).append('\n');
            spaBlock.append("VITE_AUTH_CLIENT_ID=").append(a.app.getClientId()).append("\n\n");
        }
        StringBuilder backendBlock = new StringBuilder();
        String firstBackend = null;
        for (AppInfo a : apps) {
            if (!"CONFIDENTIAL_BACKEND".equals(a.profile)) continue;
            String cid = a.app.getClientId();
            String cidUpper = cid.toUpperCase().replace('-', '_');
            if (firstBackend == null) firstBackend = cid;
            backendBlock.append("# Backend client: ").append(cid).append('\n');
            backendBlock.append(cidUpper).append("_CLIENT_ID=").append(cid).append('\n');
            backendBlock.append(cidUpper).append("_CLIENT_SECRET=<paste from auth-manager UI → Apps → ")
                .append(cid).append(" → Reveal>\n");
            backendBlock.append("AUTH_LIB_CLIENT_ID=").append(cid).append("\n\n");
        }
        StringBuilder saBlock = new StringBuilder();
        for (AppInfo a : apps) {
            if (!"SERVICE_ACCOUNT_ONLY".equals(a.profile)) continue;
            String cid = a.app.getClientId();
            String cidUpper = cid.toUpperCase().replace('-', '_');
            saBlock.append("# Service account (m2m) — for calls between services\n");
            saBlock.append("# ").append(cidUpper).append("_CLIENT_ID=").append(cid).append('\n');
            saBlock.append("# ").append(cidUpper).append("_CLIENT_SECRET=<paste from auth-manager UI → Apps → ")
                .append(cid).append(" → Reveal>\n\n");
        }
        String spa = spaBlock.length() == 0 ? "# (no SPA clients registered)" : spaBlock.toString().stripTrailing();
        String backend = backendBlock.length() == 0 ? "# (no backend clients registered)" : backendBlock.toString().stripTrailing();
        String sa = saBlock.length() == 0 ? "# (no service-account clients registered)" : saBlock.toString().stripTrailing();
        return ("""
            # Auth platform integration — {{tenantName}}
            # Mode: Direct OIDC (tenant-managed ingress)
            # Generated {{timestamp}} from auth-manager onboarding bundle.

            AUTH_LIB_ISSUER_URI={{issuer}}
            AUTH_LIB_PERMISSIONS_SOURCE=claims
            KC_BASE={{kcBase}}

            # Frontend (SPA)
            {{spaBlock}}

            # Backend
            {{backendBlock}}

            # Service account (m2m)
            {{serviceAccountBlock}}
            {{dbBlock}}
            """)
            .replace("{{tenantName}}", t.getDisplayName())
            .replace("{{timestamp}}", Instant.now().toString())
            .replace("{{issuer}}", issuer)
            .replace("{{kcBase}}", KC_BASE)
            .replace("{{spaBlock}}", spa)
            .replace("{{backendBlock}}", backend)
            .replace("{{serviceAccountBlock}}", sa)
            .replace("{{dbBlock}}", dbBlock)
            .stripTrailing() + "\n";
    }

    /**
     * Optional Managed Postgres connection block. Emitted only when the
     * tenant has actually provisioned a managed DB on the shared cluster
     * (we check via {@code TenantDatabaseService#existsFor}). The password
     * is NOT included — same reveal-once pattern as backend client
     * secrets, operator must copy from the Data Services tab.
     */
    private String renderDbBlock(String slug, boolean dbProvisioned) {
        if (!dbProvisioned) return "";
        String dbName = "t_" + slug.replace('-', '_');
        return ("""

            # Managed Postgres (HA, 3-replica on shared CNPG cluster)
            DATABASE_HOST=platform-pg-rw.auth-platform.svc.cluster.local
            DATABASE_PORT=5432
            DATABASE_NAME={{dbName}}
            DATABASE_USERNAME={{dbName}}
            DATABASE_PASSWORD=<paste from auth-manager UI → Data Services tab>
            DATABASE_URL=jdbc:postgresql://platform-pg-rw.auth-platform.svc.cluster.local:5432/{{dbName}}""")
            .replace("{{dbName}}", dbName);
    }

    private String renderHelm(String issuer, String slug, List<AppInfo> apps, boolean bffMode) {
        if (bffMode) {
            String clientId = firstBackendClientId(apps);
            StringBuilder bffBackendClients = new StringBuilder();
            boolean anyBackendBff = apps.stream().anyMatch(a -> "CONFIDENTIAL_BACKEND".equals(a.profile));
            if (anyBackendBff) {
                bffBackendClients.append("  backendClients:\n");
                for (AppInfo a : apps) {
                    if (!"CONFIDENTIAL_BACKEND".equals(a.profile)) continue;
                    String cid = a.app.getClientId();
                    bffBackendClients.append("    - clientId: ").append(cid).append('\n');
                    bffBackendClients.append("      clientSecretRef:\n");
                    bffBackendClients.append("        secretName: ").append(slug).append("-auth-secrets\n");
                    bffBackendClients.append("        key: ").append(cid).append("-client-secret\n");
                }
            }
            return ("""
                # Snippet to merge into your chart's values.yaml
                # Mode: Platform-edge BFF

                auth:
                  mode: bff
                  issuerUri: {{issuer}}
                  clientId: {{clientId}}
                  permissionsSource: claims
                  tenantSlug: {{slug}}
                {{helmBackendClients}}
                """)
                .replace("{{issuer}}", issuer)
                .replace("{{clientId}}", clientId)
                .replace("{{slug}}", slug)
                .replace("{{helmBackendClients}}", bffBackendClients.toString().stripTrailing());
        }

        StringBuilder backendBlock = new StringBuilder();
        boolean anyBackend = apps.stream().anyMatch(a -> "CONFIDENTIAL_BACKEND".equals(a.profile));
        if (anyBackend) {
            backendBlock.append("  backendClients:\n");
            for (AppInfo a : apps) {
                if (!"CONFIDENTIAL_BACKEND".equals(a.profile)) continue;
                String cid = a.app.getClientId();
                backendBlock.append("    - clientId: ").append(cid).append('\n');
                backendBlock.append("      clientSecretRef:\n");
                backendBlock.append("        secretName: ").append(slug).append("-auth-secrets\n");
                backendBlock.append("        key: ").append(cid).append("-client-secret\n");
            }
        }
        StringBuilder spaBlock = new StringBuilder();
        boolean anySpa = apps.stream().anyMatch(a -> "SPA_PKCE".equals(a.profile));
        if (anySpa) {
            spaBlock.append("  spaClients:\n");
            for (AppInfo a : apps) {
                if (!"SPA_PKCE".equals(a.profile)) continue;
                spaBlock.append("    - clientId: ").append(a.app.getClientId()).append('\n');
            }
        }
        return ("""
            # Snippet to merge into your chart's values.yaml
            # Mode: Direct OIDC

            auth:
              mode: direct
              issuerUri: {{issuer}}
              kcBase: {{kcBase}}
              permissionsSource: claims
              tenantSlug: {{slug}}
            {{helmBackendClients}}
            {{helmSpaClients}}
            """)
            .replace("{{issuer}}", issuer)
            .replace("{{kcBase}}", KC_BASE)
            .replace("{{slug}}", slug)
            .replace("{{helmBackendClients}}", backendBlock.toString().stripTrailing())
            .replace("{{helmSpaClients}}", spaBlock.toString().stripTrailing());
    }

    private String renderBrokerUrls(String realmName, Set<String> enabledIdps) {
        StringBuilder sections = new StringBuilder();
        var displayNames = IdentityProvidersBootstrap.defaultDisplayNames();
        for (String id : enabledIdps) {
            String displayName = displayNames.getOrDefault(id, id);
            String console = switch (id) {
                case "google" -> "https://console.cloud.google.com/apis/credentials";
                case "github" -> "https://github.com/settings/developers";
                default -> "(check the provider's docs)";
            };
            String brokerUri = KC_BASE + "/realms/" + realmName + "/broker/" + id + "/endpoint";
            sections.append("## ").append(displayName).append("\n\n");
            sections.append("Console: ").append(console).append("\n\n");
            sections.append("Authorized redirect URI to add:\n\n");
            sections.append("```\n").append(brokerUri).append("\n```\n\n");
        }
        return ("""
            # Identity Provider OAuth Console Setup

            Add these redirect URIs in each provider's OAuth console BEFORE users try to log in via that provider.

            {{brokerSections}}""")
            .replace("{{brokerSections}}", sections.toString().stripTrailing()) + "\n";
    }

    private String renderFrontendBff() {
        return """
            # Frontend integration (Platform-edge BFF mode)

            Your browser auth is handled by the platform — your React app just needs to
            know how to trigger login on 401 and fetch with cookies.

            ## Install

            ```bash
            npm install @mcpmesh/auth-lib-react@^0.3.0
            ```

            ## Wire up

            ```tsx
            import { PlatformAuthProvider } from '@mcpmesh/auth-lib-react';
            import { usePermission } from '@mcpmesh/auth-lib-react/bff';

            // Top-level — no clientId or issuer needed. The provider calls
            // /_bff/me for identity AND /api/me on your tenant backend for
            // authoritative permissions, exposing one unified
            // usePlatformAuth() hook whose `permissions` Set is the union of
            // your tenant app's atomic perms.
            <PlatformAuthProvider meEndpoint="/api/me">
              <App />
            </PlatformAuthProvider>
            ```

            > Back-compat: the legacy `<BffAuthProvider>` + `<MeProvider>` stack
            > still works and is exported in 0.3.0 (marked @deprecated). New
            > code should use `PlatformAuthProvider` — it eliminates the
            > footgun where `useBffAuth().user.me.permissions` only carries the
            > 6 platform-usermanagement client roles, not your app's perms.

            ## Login / logout

            ```tsx
            function LoginButton() {
              return (
                <a href={`/_bff/login?redirect_back=${encodeURIComponent(window.location.pathname)}`}>
                  Sign in
                </a>
              );
            }

            function LogoutButton() {
              return <a href="/_bff/logout">Sign out</a>;
            }
            ```

            ## Calling your backend

            ```tsx
            async function getReports() {
              const r = await fetch('/api/reports', { credentials: 'include' });
              if (r.status === 401) {
                window.location.href = `/_bff/login?redirect_back=${encodeURIComponent(window.location.pathname)}`;
                return;
              }
              return r.json();
            }
            ```

            ## Permission checks

            ```tsx
            import { usePermission, RequirePermission } from '@mcpmesh/auth-lib-react/bff';

            const canCreate = usePermission('REPORT_CREATE');
            return canCreate ? <CreateButton /> : null;

            // Or as a gate around a subtree:
            <RequirePermission permission="REPORT_CREATE" fallback={null}>
              <CreateButton />
            </RequirePermission>
            ```

            ## What to remove from existing code

            - Any code that does OIDC redirects/code-exchange yourself
            - Any localStorage/sessionStorage token handling
            - Cookie/JWT parsing in the browser — `/_bff/me` returns parsed claims
            - All `client_id`/`client_secret`/`redirect_uri` config — platform-edge holds these
            """;
    }

    private String renderFrontendDirect(List<AppInfo> apps) {
        String spaClientId = apps.stream()
            .filter(a -> "SPA_PKCE".equals(a.profile))
            .findFirst()
            .map(a -> a.app.getClientId())
            .orElse("<your-spa-client-id>");
        return ("""
            # Frontend integration (Direct OIDC mode)

            Your browser holds the access token (PKCE). The lib handles the OIDC
            dance against KC directly.

            ## Install

            ```bash
            npm install @mcpmesh/auth-lib-react@^0.3.0
            ```

            ## Wire up

            ```tsx
            import { AuthProvider, useAuth } from '@mcpmesh/auth-lib-react';

            // Top-level
            <AuthProvider
              issuer={import.meta.env.VITE_AUTH_LIB_ISSUER_URI}
              clientId="{{spaClientId}}"
              redirectUri={window.location.origin + '/auth/callback'}
            >
              <App />
            </AuthProvider>

            // In any component
            const { user, permissions, login, logout } = useAuth();
            if (!user) return <button onClick={login}>Sign in</button>;
            ```

            ## Permission checks

            ```tsx
            import { Can } from '@mcpmesh/auth-lib-react';
            <Can perm="REPORT_CREATE"><CreateReportButton /></Can>
            ```

            ## What to remove from your existing code

            - Any custom JWT decode utilities — use `useAuth().claims` instead
            - Any cookie/session handling — the lib handles it
            - Any role-string checks — switch to permission-based `<Can perm="..." />`
            """)
            .replace("{{spaClientId}}", spaClientId);
    }

    private String renderBackendJava(Tenant t, String realmName, String slug, String issuer, List<AppInfo> apps, boolean bffMode) {
        String firstBackend = firstBackendClientId(apps);
        String bearerOrigin = bffMode
            ? "Platform-edge issues your service the `Authorization: Bearer` header after translating "
              + "from the browser's `bff_sid` cookie. Your backend never sees the cookie — it just "
              + "validates the Bearer token as it would any OIDC-protected resource."
            : "The browser (or your own BFF) attaches `Authorization: Bearer <access_token>` to each request.";

        String backendClientCredsSection = "";
        boolean anyBackendApp = apps.stream().anyMatch(a -> "CONFIDENTIAL_BACKEND".equals(a.profile));
        if (bffMode && anyBackendApp) {
            String upper = envVarName(firstBackend);
            backendClientCredsSection = ("""

                ## Backend client credentials (when your service calls others)

                Your `{{firstBackend}}` client has a client_secret in KC that you can
                use for service-to-service calls. The secret is NOT in this bundle — copy it
                from auth-manager UI → Apps → {{firstBackend}} → Reveal, and store it
                as `{{upper}}_CLIENT_SECRET` in your service's secret store.

                Example client_credentials grant:

                ```bash
                curl -s -X POST "{{issuer}}/protocol/openid-connect/token" \\
                  -d "grant_type=client_credentials" \\
                  -d "client_id={{firstBackend}}" \\
                  -d "client_secret=${{upper}}_CLIENT_SECRET"
                ```

                The returned `access_token` is a JWT that other backends can validate the
                same way as user tokens (audience matches your client_id).
                """)
                .replace("{{firstBackend}}", firstBackend)
                .replace("{{upper}}", upper)
                .replace("{{issuer}}", issuer)
                .stripTrailing();
        }

        return ("""
            # Backend integration (Java / Spring)

            ## Add dependency

            ```xml
            <dependency>
              <groupId>io.mcp-mesh</groupId>
              <artifactId>mcp-mesh-auth-lib</artifactId>
              <version>0.3.1</version>
            </dependency>
            ```

            ## Configure

            `application.yaml`:
            ```yaml
            auth-lib:
              issuer-uri: ${AUTH_LIB_ISSUER_URI}
              client-id: ${AUTH_LIB_CLIENT_ID:{{firstBackend}}}
              client-secret: ${AUTH_LIB_CLIENT_SECRET}
              cache:
                # enabled=true + no Redis = in-process per-replica map (default).
                # enabled=true + Redis    = shared across replicas (see below).
                # enabled=false           = bypass cache; every check hits KC UMA.
                enabled: true
            ```

            > **Redis is optional.** As of auth-lib `0.3.1`, tenants who want a
            > Redis-backed permission cache need to add `spring-boot-starter-data-redis`
            > to their pom — 0.3.1 no longer requires the JAR on the classpath even
            > for in-memory mode (0.3.0 did, due to a typed ctor param). Leave the
            > starter out and the lib uses an in-process cache; add it and configure
            > `spring.data.redis.*` (see "Multi-replica caching" below) to enable the
            > Redis-backed cache. Set `auth-lib.cache.enabled: false` to skip caching
            > entirely.

            ## Where does the Bearer come from?

            {{bearerOrigin}}
            {{backendClientCredsSection}}

            ## Use

            Method-level permission checks:
            ```java
            @GetMapping("/reports")
            @RequirePermission("REPORT_VIEW_ANY")
            public List<Report> list() { ... }
            ```

            Programmatic checks:
            ```java
            @Autowired AuthContext authCtx;
            if (!authCtx.has("REPORT_CREATE")) throw new ForbiddenException();
            ```

            User identity:
            ```java
            authCtx.userId()    // KC subject (UUID)
            authCtx.email()     // user email
            authCtx.tenant()    // tenant slug
            ```

            ## What to remove

            - Any custom `@PreAuthorize` SpEL expressions hand-decoding JWT roles
            - Any custom Filter that pulls claims out of headers — the lib does it
            - Any role-name string constants — replace with permission IDs from your manifest

            ## Local development — get a test token

            Use the client_credentials grant to mint a token directly without a
            browser:

            ```bash
            curl -s -X POST "{{issuer}}/protocol/openid-connect/token" \\
              -d "grant_type=client_credentials" \\
              -d "client_id={{firstBackend}}" \\
              -d "client_secret=$AUTH_LIB_CLIENT_SECRET" \\
              | jq -r '.access_token'
            ```

            Then test with:
            ```bash
            curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/me
            ```

            ## Multi-replica caching (optional)

            The auth-lib cache is in-memory per pod by default. For shared cache
            across multiple replicas, point Spring Data Redis at the platform's
            shared sentinel cluster:

            ```yaml
            spring:
              data:
                redis:
                  sentinel:
                    master: mymaster
                    nodes:
                      - platform-redis-node-0.platform-redis-headless.auth-platform.svc.cluster.local:26379
                      - platform-redis-node-1.platform-redis-headless.auth-platform.svc.cluster.local:26379
                      - platform-redis-node-2.platform-redis-headless.auth-platform.svc.cluster.local:26379
            ```

            auth-lib auto-detects the Spring Redis bean and uses it. If Redis is
            unreachable at runtime the lib logs a warning + falls back to in-memory
            caching transparently.

            ## /me endpoint

            auth-lib `0.3.0+` ships `MeResponseBuilder.fromJwt(...)` — a one-liner
            that pulls `resource_access.{{firstBackend}}.roles[]` out of the JWT,
            uppercases them into a `Set<String>`, and assembles a `MeResponse`
            matching the Python lib's `build_me_response(...)` shape. Frontends
            see the same `/api/me` contract regardless of backend language.

            ```java
            import io.mcpmesh.auth.lib.dto.MeResponse;
            import io.mcpmesh.auth.lib.dto.MeResponseBuilder;
            import org.springframework.security.core.annotation.AuthenticationPrincipal;
            import org.springframework.security.oauth2.jwt.Jwt;
            import org.springframework.web.bind.annotation.GetMapping;
            import org.springframework.web.bind.annotation.RestController;

            @RestController
            public class MeController {

                @GetMapping("/api/me")
                public MeResponse me(@AuthenticationPrincipal Jwt jwt) {
                    return MeResponseBuilder.fromJwt(jwt, "{{firstBackend}}", new MeResponse.Tenant(
                        "{{slug}}", "{{slug}}", "{{tenantName}}", "{{realmName}}"));
                }
            }
            ```

            Pass a `tenantAdminRole` (e.g. `"OWNER"`) to the 5-arg overload to
            populate `isTenantAdmin`, or `extraPermissions` to union in static
            capability strings beyond what's in `resource_access`.

            ## Calling back into the platform admin API

            See also `07-in-cluster-vs-public.md` for the in-cluster vs public
            URL decision matrix.

            If your backend needs to list/lookup users (e.g. populate an
            instructor dropdown), do **NOT** call Keycloak's admin API directly.
            Call the platform admin API — it does the realm-management dance for
            you and requires only `USER_LIST` on `usermanagement` for your
            service account.

            ### Env convention

            ```
            AUTH_MGR_BASE=http://auth-platform-auth-manager.auth-platform.svc.cluster.local:8080
            {{upperSlug}}_TENANT_SLUG={{slug}}
            ```

            For local dev (outside the cluster), point `AUTH_MGR_BASE` at the
            public URL `https://auth.mcp-mesh.io` — same paths, just routed via
            Cloudflare so a touch slower.

            ### Token

            You're already minting a `client_credentials` token using
            `AUTH_LIB_CLIENT_ID` / `AUTH_LIB_CLIENT_SECRET` (your backend
            client). That same bearer works for the admin API — no separate
            credentials needed. Required permission: `USER_LIST` on
            `usermanagement`, configured at wizard time via "Service account
            permissions" or later via Apps → service-account → permissions PUT.

            ### Example: list users by realm composite role

            ```java
            import org.springframework.web.client.RestClient;
            import java.util.List;
            import java.util.Map;

            public class PlatformAdminClient {

                private static final String AUTH_MGR_BASE =
                    System.getenv().getOrDefault("AUTH_MGR_BASE",
                        "http://auth-platform-auth-manager.auth-platform.svc.cluster.local:8080");
                private static final String TENANT_SLUG =
                    System.getenv().getOrDefault("{{upperSlug}}_TENANT_SLUG", "{{slug}}");

                private final RestClient http = RestClient.create();

                public List<Map<String, Object>> listUsersByRole(String role,
                                                                 String saToken,
                                                                 int first, int max) {
                    String url = AUTH_MGR_BASE + "/api/v1/tenants/" + TENANT_SLUG
                        + "/users?role=" + role
                        + "&first=" + first + "&max=" + max;
                    @SuppressWarnings("unchecked")
                    Map<String, Object> body = http.get()
                        .uri(url)
                        .header("Authorization", "Bearer " + saToken)
                        .retrieve()
                        .body(Map.class);
                    return (List<Map<String, Object>>) body.get("items");
                }
            }
            ```

            Response shape:

            ```json
            {
              "items": [
                { "id": "uuid", "email": "...", "firstName": "...", "lastName": "...", "username": "..." }
              ],
              "first": 0,
              "max": 200,
              "totalItems": 42
            }
            ```

            ### Useful endpoints

            - `GET /api/v1/tenants/{slug}/users?role=X&search=Y` — list users (paged)
            - `GET /api/v1/tenants/{slug}/users/{userId}` — lookup one user
            - `POST /api/v1/tenants/{slug}/users` — invite a user
            - `PUT /api/v1/tenants/{slug}/users/{userId}/roles` — update assigned roles

            Role names come from your tenant manifest — download the latest from
            auth-manager UI → Permissions tab → Download manifest.
            """)
            .replace("{{tenantName}}", t.getDisplayName())
            .replace("{{realmName}}", realmName)
            .replace("{{slug}}", slug)
            .replace("{{upperSlug}}", slug.toUpperCase(java.util.Locale.ROOT).replace('-', '_'))
            .replace("{{firstBackend}}", firstBackend)
            .replace("{{bearerOrigin}}", bearerOrigin)
            .replace("{{backendClientCredsSection}}", backendClientCredsSection)
            .replace("{{issuer}}", issuer);
    }

    private String renderBackendPython(Tenant t, String realmName, String slug, String issuer,
                                        List<AppInfo> apps, boolean bffMode) {
        String firstBackend = firstBackendClientId(apps);
        String bearerOrigin = bffMode
            ? "Platform-edge issues your service the `Authorization: Bearer` header after translating "
              + "from the browser's `bff_sid` cookie. Your backend never sees the cookie — it just "
              + "validates the Bearer token as it would any OIDC-protected resource."
            : "The browser (or your own BFF) attaches `Authorization: Bearer <access_token>` to each request.";

        return ("""
            # Backend integration (Python / FastAPI)

            ## Install

            ```bash
            pip install mcp-mesh-auth-lib==0.1.0
            ```

            ## Configure (env vars)

            ```bash
            AUTH_LIB_ISSUER_URI={{issuer}}
            AUTH_LIB_CLIENT_ID={{firstBackend}}
            AUTH_LIB_CLIENT_SECRET=<from auth-manager UI → Apps → {{firstBackend}} → Reveal>
            # Optional: comma-separated extra audiences if you serve multiple backends
            # AUTH_LIB_AUDIENCES=other-backend,another-one
            AUTH_LIB_PERMISSIONS_SOURCE=claims
            ```

            ## Initialize the lib

            ```python
            from fastapi import Depends, FastAPI
            from mcpmesh_auth_lib import (
                Tenant, auth_lib_init, build_me_response,
                current_user, require_permission,
            )

            app = FastAPI()
            auth_lib_init(app)  # reads AUTH_LIB_* env vars

            TENANT = Tenant(
                id="{{slug}}",
                slug="{{slug}}",
                display_name="{{tenantName}}",
                realm_name="{{realmName}}",
            )
            ```

            ## Where does the Bearer come from?

            {{bearerOrigin}}

            ## Protect routes

            ```python
            @app.get("/api/reports")
            def list_reports(claims: dict = Depends(current_user)):
                return [...]

            @app.post("/api/reports")
            def create_report(
                claims: dict = Depends(current_user),
                _: None = Depends(require_permission("REPORT_CREATE")),
            ):
                ...
            ```

            ## /me endpoint

            ```python
            @app.get("/api/me")
            def me(claims: dict = Depends(current_user)):
                return build_me_response(
                    claims,
                    app.state.auth_lib_permissions,
                    TENANT,
                    raw_token=claims["_raw_token"],
                ).model_dump(by_alias=True)
            ```

            ## Identity + permission checks programmatically

            ```python
            sub = claims["sub"]            # KC subject UUID
            email = claims.get("email")
            permissions = app.state.auth_lib_permissions.all_for(
                token=claims["_raw_token"], claims=claims,
            )
            if "REPORT_CREATE" not in permissions:
                raise HTTPException(status_code=403)
            ```

            ## What to remove from existing code

            - Custom JWT decoding without signature verification — the lib uses PyJWKClient and validates against the KC issuer's JWKS
            - Custom Redis-backed session stores for tokens — platform-edge handles browser sessions; your backend only sees Bearer
            - Any role-string checks against ad-hoc role names — use permission IDs from your manifest

            ## Local development — get a test token

            ```bash
            TOKEN=$(curl -s -X POST "{{issuer}}/protocol/openid-connect/token" \\
              -d "grant_type=client_credentials" \\
              -d "client_id={{firstBackend}}" \\
              -d "client_secret=$AUTH_LIB_CLIENT_SECRET" \\
              | jq -r '.access_token')

            curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/me
            ```

            ## Calling back into the platform admin API

            See also `07-in-cluster-vs-public.md` for the in-cluster vs public
            URL decision matrix.

            If your backend needs to list/lookup users (e.g. populate an
            instructor dropdown), do **NOT** call Keycloak's admin API directly.
            Call the platform admin API — it does the realm-management dance for
            you and requires only `USER_LIST` on `usermanagement` for your
            service account.

            ### Env convention

            ```
            AUTH_MGR_BASE=http://auth-platform-auth-manager.auth-platform.svc.cluster.local:8080
            {{upperSlug}}_TENANT_SLUG={{slug}}
            ```

            For local dev (outside the cluster), point `AUTH_MGR_BASE` at the
            public URL `https://auth.mcp-mesh.io` — same paths, just routed via
            Cloudflare so a touch slower.

            ### Token

            You're already minting a `client_credentials` token using
            `AUTH_LIB_CLIENT_ID` / `AUTH_LIB_CLIENT_SECRET` (your backend
            client). That same bearer works for the admin API — no separate
            credentials needed. Required permission: `USER_LIST` on
            `usermanagement`, configured at wizard time via "Service account
            permissions" or later via Apps → service-account → permissions PUT.

            ### Example: list users by realm composite role

            ```python
            import os
            import httpx

            AUTH_MGR_BASE = os.environ.get(
                "AUTH_MGR_BASE",
                "http://auth-platform-auth-manager.auth-platform.svc.cluster.local:8080",
            )
            TENANT_SLUG = os.environ.get("{{upperSlug}}_TENANT_SLUG", "{{slug}}")


            def list_users_by_role(role: str, sa_token: str, first: int = 0, max_results: int = 200) -> dict:
                url = f"{AUTH_MGR_BASE}/api/v1/tenants/{TENANT_SLUG}/users"
                params = {"role": role, "first": first, "max": max_results}
                headers = {"Authorization": f"Bearer {sa_token}"}
                r = httpx.get(url, params=params, headers=headers, timeout=10.0)
                r.raise_for_status()
                return r.json()
            ```

            Response shape:

            ```json
            {
              "items": [
                { "id": "uuid", "email": "...", "firstName": "...", "lastName": "...", "username": "..." }
              ],
              "first": 0,
              "max": 200,
              "totalItems": 42
            }
            ```

            ### Useful endpoints

            - `GET /api/v1/tenants/{slug}/users?role=X&search=Y` — list users (paged)
            - `GET /api/v1/tenants/{slug}/users/{userId}` — lookup one user
            - `POST /api/v1/tenants/{slug}/users` — invite a user
            - `PUT /api/v1/tenants/{slug}/users/{userId}/roles` — update assigned roles

            Role names come from your tenant manifest — download the latest from
            auth-manager UI → Permissions tab → Download manifest.
            """)
            .replace("{{tenantName}}", t.getDisplayName())
            .replace("{{realmName}}", realmName)
            .replace("{{slug}}", slug)
            .replace("{{upperSlug}}", slug.toUpperCase(java.util.Locale.ROOT).replace('-', '_'))
            .replace("{{issuer}}", issuer)
            .replace("{{firstBackend}}", firstBackend)
            .replace("{{bearerOrigin}}", bearerOrigin);
    }

    private String renderServiceAccount(String issuer, List<AppInfo> apps) {
        String saClientId = apps.stream()
            .filter(a -> "SERVICE_ACCOUNT_ONLY".equals(a.profile))
            .findFirst()
            .map(a -> a.app.getClientId())
            .orElse("<your-sa-client-id>");
        return ("""
            # Service-to-service calls (m2m)

            Your tenant has the `{{saClientId}}` service-account client. Use it to call
            other services with your own identity (no end-user involved).

            ## Get a token

            ```bash
            curl -s -X POST "{{issuer}}/protocol/openid-connect/token" \\
              -d "grant_type=client_credentials" \\
              -d "client_id={{saClientId}}" \\
              -d "client_secret=$SA_CLIENT_SECRET"
            ```

            The response includes `access_token` — a JWT valid for ~5 minutes by default.

            ## In Java (using the Spring lib)

            ```java
            @Autowired ServiceAccountTokenProvider sa;
            String token = sa.getToken();  // cached + auto-refreshed
            WebClient.builder()
                .defaultHeader("Authorization", "Bearer " + token)
                .build();
            ```

            ## Permissions

            Service accounts get their permissions from KC roles assigned to the
            service-account user (auto-created per client). Manage these from
            auth-manager UI → Apps → {{saClientId}} → Service-account perms.
            """)
            .replace("{{saClientId}}", saClientId)
            .replace("{{issuer}}", issuer);
    }

    private String renderTheming(String slug) {
        return ("""
            # Login page theming (optional)

            Your tenant ships with the default mcp-mesh login theme. To customize, you'll
            download a starter kit (the KC theme skeleton with placeholder logo + CSS),
            edit it locally, zip it back up, and upload via the Branding tab.

            ## Step 1 — Download the starter kit

            1. Open auth-manager UI: https://auth.mcp-mesh.io/admin/tenants/{{slug}}
            2. Go to the **Branding** tab
            3. Click **Download starter** → saves `t-{{slug}}-starter.zip`

            What's inside the starter:
            - `theme.properties` — theme metadata
            - `login/resources/css/custom.css` — your CSS overrides go here
            - `login/resources/img/logo.svg` — placeholder logo to replace
            - `login/messages/messages_en.properties` — custom copy (page titles, button labels)

            ## Step 2 — Customize

            Edit locally:
            - Replace `login/resources/img/logo.svg` with your logo (SVG or PNG, ~200×200)
            - Add CSS overrides to `custom.css`. We use PatternFly v5 selectors —
              `.pf-v5-c-login__header`, `.pf-v5-c-brand`, etc.
            - Tweak copy in `messages_en.properties` if needed

            ## Step 3 — Upload

            1. Re-zip the contents (NOT the parent directory — zip the files at the top level)
            2. Back in the Branding tab, drop the zip into the upload zone (or click to pick)
            3. We pre-scan every file and reject anything that could execute code in the
               user's browser (no remote URLs in CSS, no script tags in SVGs, etc.)
            4. Click apply; changes take effect within ~30 seconds (we sync to S3 and a
               sidecar materializer reloads KC pods automatically — no pod restart)

            ## Constraints

            - Max upload size: 5 MB
            - Allowed file types: `.css`, `.svg`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.woff`, `.woff2`, `.ttf`, `.properties`, `.html` (FreeMarker templates), `.json`
            - No external URLs in CSS (`@import` from CDN, `url(https://…)` are rejected)
            - SVGs are scrubbed for `<script>` and event handler attributes

            ## Tip — iterate fast

            The Branding tab shows a "rolling out X%" badge while the theme propagates.
            Open a private/incognito window with `https://auth.mcp-mesh.io/auth/realms/t-{{slug}}/account`
            to preview the login styling without bouncing yourself out of the admin UI.
            """)
            .replace("{{slug}}", slug);
    }

    private String renderMigration(String realmName) {
        return ("""
            # Migrating existing users

            If your service already has users (e.g., in a local DB), here's how to map them to the new realm.

            ## Strategy: match by email

            KC subjects (sub claim) will be NEW UUIDs assigned by Keycloak at first login or import — they won't match your existing user IDs. The reliable join key is **email**.

            ## Recommended approach

            1. **Don't bulk import.** Let users log in with social providers (Google/GitHub) and KC will create accounts lazily.
            2. **On first login**, your backend should:
               ```java
               var kcSub = authCtx.userId();
               var email = authCtx.email();
               User existing = userRepo.findByEmail(email);
               if (existing != null && existing.getKcSub() == null) {
                   existing.setKcSub(kcSub);
                   userRepo.save(existing);  // backfill — done once per user
               }
               ```
            3. After backfill, use `kcSub` as the canonical join key. Email can still change; sub cannot.

            ## If you must bulk import

            Use the KC admin API at `{{kcBase}}/admin/realms/{{realmName}}/users` with an admin token. But prefer lazy — fewer ways to go wrong.
            """)
            .replace("{{kcBase}}", KC_BASE)
            .replace("{{realmName}}", realmName);
    }

    private String renderInClusterVsPublic(String slug, String realmName) {
        return ("""
            # In-cluster vs public URLs

            > See also `03-backend-java.md` / `03-backend-python.md` for the
            > code that uses these URLs.

            Three platform URLs your backend talks to. Two should be in-cluster,
            one MUST stay public. Get this wrong and you'll either round-trip
            through Cloudflare unnecessarily or get JWT validation failures.

            ## Decision table

            | URL purpose | Env var | In-cluster value | Public value | Use which? |
            |---|---|---|---|---|
            | JWT issuer (JWKS + UMA) | `AUTH_LIB_ISSUER_URI` | n/a | `{{kcBase}}/realms/{{realmName}}` | **Public only** |
            | KC token endpoint | `KC_TOKEN_ENDPOINT` or `KC_BASE` | `http://platform-kc-keycloak.auth-platform.svc.cluster.local:80` | `{{kcBase}}` | Either; in-cluster faster |
            | Platform admin API | `AUTH_MGR_BASE` | `{{authMgrBase}}` | `https://auth.mcp-mesh.io` | In-cluster strongly preferred |

            ## Why the issuer URI must be public

            The `AUTH_LIB_ISSUER_URI` env var must be the PUBLIC URL
            `{{kcBase}}/realms/{{realmName}}` — NOT the in-cluster
            `http://platform-kc-keycloak.auth-platform.svc.cluster.local:80/realms/{{realmName}}`.

            auth-lib uses this URL both for JWKS fetch and for UMA permission
            lookups, and the URL **must match the JWT's `iss` claim exactly** —
            otherwise signature validation fails with:

            ```
            Rejecting JWT with unknown issuer
            ```

            (grep your logs for that string and you'll land back here). This is
            the same reason auth-manager itself uses the public URL — the
            "trusted-issuer prefix must match KC_HOSTNAME exactly" gotcha in the
            auth-platform repo.

            ## JWKS fetching goes over public DNS — that's fine

            Since the issuer URL is public, the JWKS fetch auth-lib does (to
            verify JWT signatures) WILL traverse Cloudflare. Don't try to "fix"
            this with a /etc/hosts override or an in-cluster rewrite — JWKS is
            fetched rarely and aggressively cached (default ~10 minutes), so the
            perf cost is negligible. Forcing it through an in-cluster URL just
            breaks issuer matching for no real gain.

            ## KC token endpoint — pick whatever

            For `client_credentials` grants (minting service-account tokens),
            either in-cluster or public works because the token endpoint doesn't
            care about issuer-matching — it issues tokens, it doesn't validate
            them. In-cluster is meaningfully faster (no TLS handshake, no
            Cloudflare hop). Recommend in-cluster.

            ## Platform admin API — prefer in-cluster

            `AUTH_MGR_BASE` should default to the in-cluster service DNS:
            `{{authMgrBase}}`. The same bearer your backend mints for KC works
            against `/api/v1/tenants/{{slug}}/...` (see the backend docs for
            the code). Use the public URL `https://auth.mcp-mesh.io` only for
            local dev or one-off scripts running outside the cluster.

            ## Gotcha — no `/auth/` on the in-cluster KC URL

            > The in-cluster KC URL has NO `/auth/` prefix (KC's
            > `KC_HTTP_RELATIVE_PATH=/`). The `/auth/` only exists at the public
            > hostname because `KC_HOSTNAME` includes it. Copying
            > `https://auth.mcp-mesh.io/auth/realms/...` and just replacing the
            > host will 404.

            ## Egress consequences

            All three Cloudflare-bound calls are visible at the edge and counted
            against tunnel quota — including JWKS fetches and any admin API or
            token calls you forget to switch to in-cluster URLs. In-cluster
            traffic stays inside the pod network and never hits the tunnel. For
            a chatty service hitting the admin API on every request, the
            difference is real.
            """)
            .replace("{{slug}}", slug)
            .replace("{{realmName}}", realmName)
            .replace("{{kcBase}}", KC_BASE)
            .replace("{{authMgrBase}}", AUTH_MGR_BASE);
    }

    /**
     * Renders the tenant's current permission catalog + role bundles as YAML.
     * For a fresh tenant with nothing configured, emits a commented starter
     * with the first backend client_id pre-filled. Failures degrade to an
     * apologetic placeholder so the bundle download never breaks.
     */
    private String renderTenantManifest(Tenant tenant, List<AppInfo> apps) {
        try {
            TenantManifest manifest = manifestService.generate(tenant.getSlug());
            String firstBackend = apps.stream()
                .filter(a -> "CONFIDENTIAL_BACKEND".equals(a.profile)
                          || "SERVICE_ACCOUNT_ONLY".equals(a.profile))
                .findFirst()
                .map(a -> a.app.getClientId())
                .orElse(null);
            return TenantManifestYamlRenderer.render(manifestYamlMapper, tenant, manifest, firstBackend);
        } catch (Exception e) {
            log.warn("renderTenantManifest({}) failed: {}", tenant.getSlug(), e.getMessage());
            return "# Manifest could not be generated at download time ("
                + e.getMessage() + ").\n"
                + "# Re-download the bundle or fetch from the Permissions tab → Download manifest.\n";
        }
    }

    private record AppInfo(App app, String profile) {}
}
