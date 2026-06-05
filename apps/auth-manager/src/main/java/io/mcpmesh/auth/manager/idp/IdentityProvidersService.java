package io.mcpmesh.auth.manager.idp;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.authflow.LoginMethodService;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.IdentityProvidersBootstrap;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.service.TenantService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.LinkedHashMap;
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
    private final TenantRepository tenantRepo;
    private final IdentityProvidersBootstrap idp;
    private final KeycloakAdminService keycloak;
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
                                    TenantRepository tenantRepo,
                                    IdentityProvidersBootstrap idp,
                                    KeycloakAdminService keycloak,
                                    AuditService audit,
                                    @Lazy LoginMethodService loginMethods) {
        this.tenants = tenants;
        this.tenantRepo = tenantRepo;
        this.idp = idp;
        this.keycloak = keycloak;
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

    @Transactional
    public IdentityProviderDto setEnabled(String slug, String providerId, boolean wantEnabled, String actor) {
        if (!IdentityProvidersBootstrap.SUPPORTED_PROVIDERS.contains(providerId)) {
            throw new IllegalArgumentException("Unsupported provider: " + providerId);
        }
        Tenant tenant = tenants.getBySlug(slug);

        boolean currentlyEnabled = idp.isEnabled(tenant.getRealmName(), providerId);
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("tenant_slug", slug);
        details.put("realm", tenant.getRealmName());
        details.put("provider", providerId);
        details.put("enabled", wantEnabled);
        details.put("disabledIdps", new ArrayList<>(tenant.getDisabledIdps()));

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
                // Clear the operator-disabled mark FIRST so a concurrent
                // bootstrap pass observes the alias as re-enabled.
                tenant.setIdpDisabled(providerId, false);
                tenantRepo.save(tenant);
                idp.addProvider(tenant.getRealmName(), providerId);
                details.put("disabledIdps", new ArrayList<>(tenant.getDisabledIdps()));
                audit.recordSuccess(actor, ACTOR_KIND, tenant.getId(),
                    "idp.enable", "identity_provider", providerId,
                    Map.of("enabled", true), details);
            } else if (!wantEnabled && currentlyEnabled) {
                // Record the operator's intent BEFORE removing from KC so a
                // restart race can't re-create the IdP between the remove
                // call and the persist.
                tenant.setIdpDisabled(providerId, true);
                tenantRepo.save(tenant);
                idp.removeProvider(tenant.getRealmName(), providerId);
                details.put("disabledIdps", new ArrayList<>(tenant.getDisabledIdps()));
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

    /** Current invite-only posture for the tenant (persisted DB flag). */
    public RegistrationStateDto getRegistrationState(String slug) {
        Tenant tenant = tenants.getBySlug(slug);
        boolean inviteOnly = tenant.isInviteOnly();
        return new RegistrationStateDto(inviteOnly, !inviteOnly);
    }

    /**
     * Toggles the per-tenant invite-only posture: persists the DB flag, applies
     * the matching KC change (registrationAllowed + create-if-unique
     * requirement), and writes an audit entry. Mirrors {@link #setEnabled}.
     */
    @Transactional
    public RegistrationStateDto setInviteOnly(String slug, boolean inviteOnly, String actor) {
        Tenant tenant = tenants.getBySlug(slug);

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("tenant_slug", slug);
        details.put("realm", tenant.getRealmName());
        details.put("inviteOnly", inviteOnly);

        try {
            // Record intent BEFORE the KC change so a restart race re-asserts it.
            tenant.setInviteOnly(inviteOnly);
            tenantRepo.save(tenant);
            keycloak.setInviteOnly(tenant.getRealmName(), inviteOnly);
            audit.recordSuccess(actor, ACTOR_KIND, tenant.getId(),
                "tenant.invite_only.set", "tenant", slug,
                Map.of("inviteOnly", inviteOnly), details);
        } catch (Exception e) {
            audit.recordFailure(actor, ACTOR_KIND, tenant.getId(),
                "tenant.invite_only.set", "tenant", slug,
                Map.of("inviteOnly", inviteOnly), e, details);
            throw e;
        }

        return new RegistrationStateDto(inviteOnly, !inviteOnly);
    }
}
