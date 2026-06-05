package io.mcpmesh.auth.manager.idp;

import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Per-tenant identity-provider listing + toggle endpoint.
 * Reads gated by {@code canSeeTenantBySlug}; toggle requires {@code canManageTenant}.
 *
 * <p>Returns 400 for unsupported provider ids and 422 (via service) when a
 * caller tries to enable a provider whose platform creds are unset.
 */
@RestController
@RequestMapping("/api/v1/tenants/{slug}/identity-providers")
public class IdentityProvidersController {

    private final IdentityProvidersService service;

    public IdentityProvidersController(IdentityProvidersService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize("@perms.hasOnTenant(#slug, 'TENANT_VIEW')")
    public List<IdentityProviderDto> list(@PathVariable String slug) {
        return service.list(slug);
    }

    @PutMapping("/{providerId}")
    @PreAuthorize("@perms.hasOnTenant(#slug, 'IDP_EDIT')")
    public IdentityProviderDto update(
        @PathVariable String slug,
        @PathVariable String providerId,
        @Valid @RequestBody UpdateProviderRequest req,
        Authentication auth
    ) {
        return service.setEnabled(slug, providerId, Boolean.TRUE.equals(req.enabled()), principal(auth));
    }

    @GetMapping("/registration")
    @PreAuthorize("@perms.hasOnTenant(#slug, 'TENANT_VIEW')")
    public RegistrationStateDto getRegistration(@PathVariable String slug) {
        return service.getRegistrationState(slug);
    }

    @PutMapping("/registration")
    @PreAuthorize("@perms.hasOnTenant(#slug, 'IDP_EDIT')")
    public RegistrationStateDto updateRegistration(
        @PathVariable String slug,
        @Valid @RequestBody UpdateRegistrationRequest req,
        Authentication auth
    ) {
        return service.setInviteOnly(slug, Boolean.TRUE.equals(req.inviteOnly()), principal(auth));
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
