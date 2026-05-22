package io.mcpmesh.auth.manager.roles;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;

/**
 * Composite-role CRUD + permissions catalog for a tenant. All reads gated by
 * {@code canSeeTenantBySlug}; mutations additionally require
 * {@code canManageTenant} (= tenant-admin or platform-admin).
 */
@RestController
@RequestMapping("/api/v1/tenants/{slug}")
public class RolesController {

    private final RolesService service;

    public RolesController(RolesService service) {
        this.service = service;
    }

    @GetMapping("/permissions")
    @PreAuthorize("@tenantSecurity.canSeeTenantBySlug(#slug)")
    public List<PermissionDto> permissions(@PathVariable String slug) {
        return service.listPermissions(slug);
    }

    @GetMapping("/roles")
    @PreAuthorize("@tenantSecurity.canSeeTenantBySlug(#slug)")
    public List<RoleDto> list(@PathVariable String slug) {
        return service.list(slug);
    }

    @GetMapping("/roles/{roleName}")
    @PreAuthorize("@tenantSecurity.canSeeTenantBySlug(#slug)")
    public RoleDto get(@PathVariable String slug, @PathVariable String roleName) {
        return service.get(slug, roleName);
    }

    @PostMapping("/roles")
    @PreAuthorize("@tenantSecurity.canManageTenant(#slug)")
    public ResponseEntity<RoleDto> create(
        @PathVariable String slug,
        @Valid @RequestBody CreateRoleRequest req,
        Authentication auth,
        UriComponentsBuilder uriBuilder
    ) {
        RoleDto created = service.create(slug, req, principal(auth));
        var location = uriBuilder.path("/api/v1/tenants/{slug}/roles/{roleName}")
            .buildAndExpand(slug, created.name()).toUri();
        return ResponseEntity.created(location).body(created);
    }

    @PutMapping("/roles/{roleName}")
    @PreAuthorize("@tenantSecurity.canManageTenant(#slug)")
    public RoleDto update(
        @PathVariable String slug,
        @PathVariable String roleName,
        @Valid @RequestBody UpdateRoleRequest req,
        Authentication auth
    ) {
        return service.update(slug, roleName, req, principal(auth));
    }

    @DeleteMapping("/roles/{roleName}")
    @PreAuthorize("@tenantSecurity.canManageTenant(#slug)")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(
        @PathVariable String slug,
        @PathVariable String roleName,
        Authentication auth
    ) {
        service.delete(slug, roleName, principal(auth));
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
