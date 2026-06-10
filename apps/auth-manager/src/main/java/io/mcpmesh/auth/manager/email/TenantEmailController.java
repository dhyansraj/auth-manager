package io.mcpmesh.auth.manager.email;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.UUID;

/**
 * UUID-keyed per-tenant email + SendGrid domain-auth endpoints.
 *
 * <pre>
 *   GET  /api/v1/tenants/{tenantId}/email                       → TenantEmailResponse
 *   PUT  /api/v1/tenants/{tenantId}/email                       → TenantEmailResponse
 *   GET  /api/v1/tenants/{tenantId}/email/rate-limit            → TenantEmailRateLimitResponse
 *   PUT  /api/v1/tenants/{tenantId}/email/rate-limit            → TenantEmailRateLimitResponse
 *   GET  /api/v1/tenants/{tenantId}/email/domain-auth           → DomainAuthResponse
 *   POST /api/v1/tenants/{tenantId}/email/domain-auth           → DomainAuthResponse
 *   POST /api/v1/tenants/{tenantId}/email/domain-auth/revalidate → DomainAuthResponse
 * </pre>
 *
 * <p>Guards mirror the Branding tab's split: read on {@code TENANT_VIEW},
 * write on {@code TENANT_EDIT}.
 */
@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/email")
public class TenantEmailController {

    private final TenantEmailService emailService;
    private final TenantDomainAuthService domainAuthService;

    public TenantEmailController(TenantEmailService emailService,
                                 TenantDomainAuthService domainAuthService) {
        this.emailService = emailService;
        this.domainAuthService = domainAuthService;
    }

    @GetMapping
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'TENANT_VIEW')")
    public TenantEmailResponse get(@PathVariable UUID tenantId) {
        return emailService.get(tenantId);
    }

    @PutMapping
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'TENANT_EDIT')")
    public TenantEmailResponse update(
        @PathVariable UUID tenantId,
        @Valid @RequestBody TenantEmailUpdateRequest req,
        Authentication auth
    ) {
        return emailService.update(tenantId, req, principal(auth));
    }

    @GetMapping("/rate-limit")
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'TENANT_VIEW')")
    public TenantEmailRateLimitResponse getRateLimit(@PathVariable UUID tenantId) {
        return emailService.getRateLimit(tenantId);
    }

    @PutMapping("/rate-limit")
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'TENANT_EDIT')")
    public TenantEmailRateLimitResponse updateRateLimit(
        @PathVariable UUID tenantId,
        @RequestBody TenantEmailRateLimitUpdateRequest req,
        Authentication auth
    ) {
        return emailService.updateRateLimit(tenantId, req, principal(auth));
    }

    @GetMapping("/domain-auth")
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'TENANT_VIEW')")
    public DomainAuthResponse domainAuthStatus(@PathVariable UUID tenantId) {
        return domainAuthService.status(tenantId);
    }

    @PostMapping("/domain-auth")
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'TENANT_EDIT')")
    @ResponseStatus(HttpStatus.OK)
    public DomainAuthResponse domainAuthStart(
        @PathVariable UUID tenantId,
        @RequestBody Map<String, String> body,
        Authentication auth
    ) {
        String domain = body == null ? null : body.get("domain");
        if (domain == null || domain.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "email.domain_required: 'domain' field is required");
        }
        return domainAuthService.start(tenantId, domain, principal(auth));
    }

    @PostMapping("/domain-auth/revalidate")
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'TENANT_EDIT')")
    public DomainAuthResponse domainAuthRevalidate(
        @PathVariable UUID tenantId,
        Authentication auth
    ) {
        return domainAuthService.revalidate(tenantId, principal(auth));
    }

    private static String principal(Authentication auth) {
        if (auth instanceof JwtAuthenticationToken jwtAuth) {
            Jwt jwt = jwtAuth.getToken();
            String pref = jwt.getClaimAsString("preferred_username");
            return pref != null ? pref : jwt.getSubject();
        }
        return "system";
    }
}
