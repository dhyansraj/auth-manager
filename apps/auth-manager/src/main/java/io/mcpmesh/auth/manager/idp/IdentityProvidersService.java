package io.mcpmesh.auth.manager.idp;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.authflow.LoginMethodService;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.IdentityProvidersBootstrap;
import io.mcpmesh.auth.manager.service.TenantService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Read + toggle the per-tenant identity-provider list. Delegates the actual
 * KC mutations to {@link IdentityProvidersBootstrap}. This service owns the
 * audit + 422-on-unavailable surface so the controller stays thin.
 */
@Service
public class IdentityProvidersService {

    private static final ActorKind ACTOR_KIND = ActorKind.USER;

    private final TenantService tenants;
    private final IdentityProvidersBootstrap idp;
    private final AuditService audit;
    private final LoginMethodService loginMethods;

    /**
     * Note the {@code @Lazy} on {@code loginMethods}: the two services have a
     * shared dependency surface (both depend on TenantService + Keycloak
     * admin) but neither needs the other at construction time — only at call
     * time. Lazy injection avoids a potential bean cycle in tests that
     * autowire both.
     */
    @Autowired
    public IdentityProvidersService(TenantService tenants,
                                    IdentityProvidersBootstrap idp,
                                    AuditService audit,
                                    @Lazy LoginMethodService loginMethods) {
        this.tenants = tenants;
        this.idp = idp;
        this.audit = audit;
        this.loginMethods = loginMethods;
    }

    public List<IdentityProviderDto> list(String slug) {
        Tenant tenant = tenants.getBySlug(slug);
        List<IdentityProviderDto> out = new ArrayList<>();
        for (var e : IdentityProvidersBootstrap.defaultDisplayNames().entrySet()) {
            String providerId = e.getKey();
            String display = e.getValue();
            boolean available = idp.isAvailable(providerId);
            boolean enabled = idp.isEnabled(tenant.getRealmName(), providerId);
            out.add(new IdentityProviderDto(providerId, display, enabled, available));
        }
        return out;
    }

    public IdentityProviderDto setEnabled(String slug, String providerId, boolean wantEnabled, String actor) {
        if (!IdentityProvidersBootstrap.SUPPORTED_PROVIDERS.contains(providerId)) {
            throw new IllegalArgumentException("Unsupported provider: " + providerId);
        }
        Tenant tenant = tenants.getBySlug(slug);

        boolean currentlyEnabled = idp.isEnabled(tenant.getRealmName(), providerId);
        Map<String, Object> details = Map.of(
            "tenant_slug", slug,
            "realm", tenant.getRealmName(),
            "provider", providerId,
            "enabled", wantEnabled
        );

        if (wantEnabled && !idp.isAvailable(providerId)) {
            var ex = new ResponseStatusException(
                org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY,
                "Platform credentials for '" + providerId + "' are not configured");
            audit.recordFailure(actor, ACTOR_KIND, tenant.getId(),
                "idp.enable", "identity_provider", providerId,
                Map.of("enabled", true), ex, details);
            throw ex;
        }

        // Phase 2 invariant: refuse to disable the last IdP when password is
        // also off. Symmetric guard to LoginMethodService.setPasswordEnabled.
        if (!wantEnabled && currentlyEnabled) {
            try {
                loginMethods.checkSetIdpEnabled(tenant.getId(), providerId, false);
            } catch (ResponseStatusException ex) {
                audit.recordFailure(actor, ACTOR_KIND, tenant.getId(),
                    "idp.disable", "identity_provider", providerId,
                    Map.of("enabled", false), ex, details);
                throw ex;
            }
        }

        try {
            if (wantEnabled && !currentlyEnabled) {
                idp.addProvider(tenant.getRealmName(), providerId);
                audit.recordSuccess(actor, ACTOR_KIND, tenant.getId(),
                    "idp.enable", "identity_provider", providerId,
                    Map.of("enabled", true), details);
            } else if (!wantEnabled && currentlyEnabled) {
                idp.removeProvider(tenant.getRealmName(), providerId);
                audit.recordSuccess(actor, ACTOR_KIND, tenant.getId(),
                    "idp.disable", "identity_provider", providerId,
                    Map.of("enabled", false), details);
            }
            // No-ops (already in desired state) do not emit audit events.
        } catch (Exception e) {
            audit.recordFailure(actor, ACTOR_KIND, tenant.getId(),
                wantEnabled ? "idp.enable" : "idp.disable",
                "identity_provider", providerId,
                Map.of("enabled", wantEnabled), e, details);
            throw e;
        }

        return new IdentityProviderDto(
            providerId,
            IdentityProvidersBootstrap.defaultDisplayNames().get(providerId),
            idp.isEnabled(tenant.getRealmName(), providerId),
            idp.isAvailable(providerId)
        );
    }
}
