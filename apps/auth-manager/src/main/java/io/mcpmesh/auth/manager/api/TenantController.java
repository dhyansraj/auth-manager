package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.api.dto.AuditEventResponse;
import io.mcpmesh.auth.manager.api.dto.CreateTenantRequest;
import io.mcpmesh.auth.manager.api.dto.PageResponse;
import io.mcpmesh.auth.manager.api.dto.TenantResponse;
import io.mcpmesh.auth.manager.domain.tenant.TenantStatus;
import io.mcpmesh.auth.manager.keycloak.IdentityProvidersBootstrap;
import io.mcpmesh.auth.manager.persistence.AuditEventRepository;
import io.mcpmesh.auth.manager.security.TenantSecurity;
import io.mcpmesh.auth.manager.service.OnboardingBundleService;
import io.mcpmesh.auth.manager.service.TenantService;
import io.mcpmesh.auth.manager.service.UsermanagementBootstrap;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/tenants")
public class TenantController {

    private static final Logger log = LoggerFactory.getLogger(TenantController.class);

    private final TenantService service;
    private final AuditEventRepository auditRepo;
    private final UsermanagementBootstrap bootstrap;
    private final IdentityProvidersBootstrap idpBootstrap;
    private final TenantSecurity tenantSecurity;
    private final OnboardingBundleService bundleService;

    public TenantController(TenantService service, AuditEventRepository auditRepo,
                            UsermanagementBootstrap bootstrap,
                            IdentityProvidersBootstrap idpBootstrap,
                            TenantSecurity tenantSecurity,
                            OnboardingBundleService bundleService) {
        this.service = service;
        this.auditRepo = auditRepo;
        this.bootstrap = bootstrap;
        this.idpBootstrap = idpBootstrap;
        this.tenantSecurity = tenantSecurity;
        this.bundleService = bundleService;
    }

    @PostMapping
    @PreAuthorize("@perms.has('TENANT_CREATE')")
    public ResponseEntity<TenantResponse> create(
        @Valid @RequestBody CreateTenantRequest req,
        UriComponentsBuilder uriBuilder
    ) {
        // TODO(security): replace "system" with the authenticated principal once
        //                 auth-lib v2 lands. See PLAN.org Phase 2.
        var t = service.create(
            req.slug(), req.displayName(), req.settings(), req.hostnames(), "system");
        if (t.getStatus() == TenantStatus.ACTIVE) {
            try {
                bootstrap.bootstrap(t, req.adminEmail(), "system");
                // Best-effort: enable Google + GitHub IdP brokering on the new realm
                // if platform OAuth creds are configured. Bootstrap logs + swallows
                // per-provider failures so tenant create stays clean.
                idpBootstrap.ensureProviders(t.getRealmName(), idpBootstrap.defaultProvidersForNewTenant());
            } catch (RuntimeException bootstrapErr) {
                // Bootstrap failed AFTER the realm + DB row were created. Mark the
                // tenant FAILED so operators can retry via /tenants/{id}/retry
                // (which is a no-op on ACTIVE tenants — the FAILED status is the
                // recovery signal).
                log.error("Tenant {} created but bootstrap failed: {}", t.getId(), bootstrapErr.getMessage(), bootstrapErr);
                t = service.markFailed(t.getId(), bootstrapErr.getMessage(), "system");
                // Re-throw so the HTTP response is 500; the global handler turns
                // RuntimeException into 500 with the message. The tenant row is now
                // FAILED so the wizard can detect + recover from this state.
                throw new RuntimeException(
                    "Tenant created but bootstrap failed (status=FAILED, /retry to recover): " + bootstrapErr.getMessage(),
                    bootstrapErr);
            }
        }
        var body = TenantResponse.from(t, service.hostnamesFor(t.getId()));
        var location = uriBuilder.path("/api/v1/tenants/{id}").buildAndExpand(t.getId()).toUri();
        return ResponseEntity.created(location).body(body);
    }

    /**
     * Platform-admin sees every active tenant. Tenant-admins (and any other
     * authenticated caller bearing a tenant-realm JWT) see only their own
     * tenant. Unauthenticated requests get 403 via the
     * {@code isAuthenticated()} guard.
     */
    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public List<TenantResponse> list() {
        if (tenantSecurity.isPlatformAdmin()) {
            return service.list().stream()
                .map(t -> TenantResponse.from(t, service.hostnamesFor(t.getId())))
                .toList();
        }
        return tenantSecurity.currentTenantId()
            .map(id -> {
                var t = service.get(id);
                return List.of(TenantResponse.from(t, service.hostnamesFor(t.getId())));
            })
            .orElse(List.of());
    }

    @GetMapping("/{id}")
    @PreAuthorize("@perms.hasOnTenantId(#id, 'TENANT_VIEW')")
    public TenantResponse get(@PathVariable UUID id) {
        var t = service.get(id);
        return TenantResponse.from(t, service.hostnamesFor(t.getId()));
    }

    @GetMapping("/by-slug/{slug}")
    @PreAuthorize("@perms.hasOnTenant(#slug, 'TENANT_VIEW')")
    public TenantResponse getBySlug(@PathVariable String slug) {
        var t = service.getBySlug(slug);
        return TenantResponse.from(t, service.hostnamesFor(t.getId()));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("@perms.has('TENANT_DELETE')")
    @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
    public void delete(@PathVariable UUID id) {
        service.softDelete(id, "system");  // TODO(security): real actor
    }

    /**
     * Hard delete: permanently removes the KC realm + theme ConfigMap +
     * tenant DB row. Irreversible — there is no resurrect after this.
     * Operators should normally use the soft delete; this exists to clean up
     * orphaned realms (e.g., from older code paths that left realms behind).
     */
    @DeleteMapping("/{id}/force")
    @PreAuthorize("@perms.has('TENANT_DELETE')")
    @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
    public void forceDelete(@PathVariable UUID id) {
        service.forceDelete(id, "system");  // TODO(security): real actor
    }

    @PostMapping("/{id}/retry")
    @PreAuthorize("@perms.has('TENANT_CREATE')")
    public TenantResponse retry(@PathVariable UUID id) {
        // TODO(security): replace "system" with the authenticated principal.
        var t = service.retryProvisioning(id, "system");
        if (t.getStatus() == TenantStatus.ACTIVE) {
            // TODO: persist adminEmail on the Tenant entity so retry() can
            //       re-send the invite. For now retry is admin-less; the user
            //       must re-trigger via a future "resend invite" endpoint.
            bootstrap.bootstrap(t, null, "system");
            idpBootstrap.ensureProviders(t.getRealmName(), idpBootstrap.defaultProvidersForNewTenant());
        }
        return TenantResponse.from(t, service.hostnamesFor(t.getId()));
    }

    @GetMapping(value = "/{id}/onboarding-bundle", produces = "application/zip")
    @PreAuthorize("@perms.hasOnTenantId(#id, 'TENANT_VIEW')")
    public ResponseEntity<byte[]> onboardingBundle(@PathVariable UUID id) {
        var t = service.get(id);
        byte[] zip = bundleService.build(id);
        String fname = t.getSlug() + "-auth-onboarding.zip";
        return ResponseEntity.ok()
            .header("Content-Disposition", "attachment; filename=\"" + fname + "\"")
            .contentType(MediaType.parseMediaType("application/zip"))
            .body(zip);
    }

    @GetMapping("/{id}/audit")
    @PreAuthorize("@perms.hasOnTenantId(#id, 'AUDIT_VIEW')")
    public PageResponse<AuditEventResponse> audit(
        @PathVariable UUID id,
        @RequestParam(defaultValue = "0")  int page,
        @RequestParam(defaultValue = "50") int size
    ) {
        // Trigger 404 if tenant doesn't exist (or was soft-deleted).
        service.get(id);
        int safeSize = Math.min(Math.max(size, 1), 200);
        return PageResponse.from(
            auditRepo.findByTenantIdOrderByOccurredAtDesc(id,
                org.springframework.data.domain.PageRequest.of(page, safeSize)),
            AuditEventResponse::from);
    }
}
