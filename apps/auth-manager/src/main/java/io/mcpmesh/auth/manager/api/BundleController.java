package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.service.BundleBaseResolver;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exposes the config-driven platform base URLs used in onboarding bundles.
 * The admin-UI wizard fetches this instead of hardcoding hostnames
 * (supersedes the 0.1.47 {@code bundleBases()} stopgap in admin-ui's
 * {@code lib/env.ts}).
 */
@RestController
@RequestMapping("/api/v1/bundle")
public class BundleController {

    private final BundleBaseResolver bases;

    public BundleController(BundleBaseResolver bases) {
        this.bases = bases;
    }

    public record BundleBasesResponse(String kcBase, String adminBase,
                                      String authMgrInClusterBase, String authMgrPublicBase) {}

    /**
     * Read-only platform config, non-tenant-scoped — gated the same way as
     * {@code GET /api/v1/tenants} (any authenticated platform/tenant JWT).
     */
    @GetMapping("/bases")
    @PreAuthorize("isAuthenticated()")
    public BundleBasesResponse getBases() {
        return new BundleBasesResponse(
            bases.kcBase(),
            bases.adminBase(),
            bases.authMgrInClusterBase(),
            bases.authMgrPublicBase());
    }
}
