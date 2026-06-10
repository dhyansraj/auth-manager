package io.mcpmesh.auth.manager.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Single source of truth for the platform base URLs embedded in tenant
 * onboarding bundles (and exposed to the admin-UI wizard via
 * {@code GET /api/v1/bundle/bases}).
 *
 * <p>CONFIG-ONLY by design — values come purely from the
 * {@code auth-manager.bundle.*} props (env-bound to
 * {@code AUTH_MANAGER_BUNDLE_*} in the helm chart). No request auto-detect:
 * deriving these from the inbound Host was considered and rejected (not
 * worth the forwarded-header trust surface). Defaults are the prod values
 * so unmigrated deploys keep working; dev overrides via
 * values-beelink-dev.yaml.
 */
@Component
public class BundleBaseResolver {

    private final String kcBase;
    private final String adminBase;
    private final String authMgrInClusterBase;
    private final String authMgrPublicBase;

    public BundleBaseResolver(
        @Value("${auth-manager.bundle.kc-base:https://auth.mcp-mesh.io/auth}") String kcBase,
        @Value("${auth-manager.bundle.admin-base:https://auth.mcp-mesh.io/admin}") String adminBase,
        @Value("${auth-manager.bundle.auth-mgr-incluster-base:http://auth-platform-auth-manager.auth-platform.svc.cluster.local:8080}") String authMgrInClusterBase,
        @Value("${auth-manager.bundle.auth-mgr-public-base:https://auth.mcp-mesh.io}") String authMgrPublicBase
    ) {
        this.kcBase = kcBase;
        this.adminBase = adminBase;
        this.authMgrInClusterBase = authMgrInClusterBase;
        this.authMgrPublicBase = authMgrPublicBase;
    }

    /** Public Keycloak base, including the {@code /auth} prefix (e.g. {@code https://auth.mcp-mesh.io/auth}). */
    public String kcBase() {
        return kcBase;
    }

    /** Public admin-UI base (e.g. {@code https://auth.mcp-mesh.io/admin}). */
    public String adminBase() {
        return adminBase;
    }

    /** In-cluster auth-manager service DNS base — for backends running inside the cluster. */
    public String authMgrInClusterBase() {
        return authMgrInClusterBase;
    }

    /** Public auth-manager base — for local dev / backends running outside the cluster. */
    public String authMgrPublicBase() {
        return authMgrPublicBase;
    }
}
