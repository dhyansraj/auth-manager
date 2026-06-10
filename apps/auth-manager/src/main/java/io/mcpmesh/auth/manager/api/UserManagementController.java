package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.api.dto.CreateUserRequest;
import io.mcpmesh.auth.manager.api.dto.UpdateUserRolesRequest;
import io.mcpmesh.auth.manager.api.dto.UserResponse;
import io.mcpmesh.auth.manager.service.UserManagementService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * UUID-keyed user management. The {@code tenantId} path segment is constrained
 * to UUID syntax so the slug-keyed twin in {@link io.mcpmesh.auth.manager.roles.UserRolesController}
 * can share the same path prefix without ambiguity (Spring otherwise can't
 * tell {@code /tenants/{slug}/users/...} apart from {@code /tenants/{uuid}/users/...}).
 */
@RestController
@RequestMapping("/api/v1/tenants/{tenantId:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}}/users")
public class UserManagementController {

    private final UserManagementService service;

    public UserManagementController(UserManagementService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'USER_LIST')")
    public Map<String, Object> list(
        @PathVariable UUID tenantId,
        @RequestParam(required = false) String search,
        @RequestParam(defaultValue = "0") int first,
        @RequestParam(defaultValue = "50") int max
    ) {
        int safeMax = Math.min(Math.max(max, 1), 200);
        var result = service.list(tenantId, search, first, safeMax);
        return Map.of(
            "items", result.items(),
            "first", result.first(),
            "max", result.max(),
            "totalItems", result.totalItems()
        );
    }

    @GetMapping("/{userId}")
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'USER_LIST')")
    public UserResponse get(@PathVariable UUID tenantId, @PathVariable String userId) {
        return service.get(tenantId, userId);
    }

    @PostMapping
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'USER_INVITE')")
    public ResponseEntity<UserResponse> create(
        @PathVariable UUID tenantId,
        @Valid @RequestBody CreateUserRequest req,
        Authentication auth,
        UriComponentsBuilder uriBuilder
    ) {
        var body = service.create(tenantId, req, principal(auth));
        var location = uriBuilder.path("/api/v1/tenants/{t}/users/{u}")
            .buildAndExpand(tenantId, body.id()).toUri();
        return ResponseEntity.created(location).body(body);
    }

    @DeleteMapping("/{userId}")
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'USER_DISABLE')")
    @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
    public void disable(@PathVariable UUID tenantId, @PathVariable String userId,
                        Authentication auth) {
        service.disable(tenantId, userId, principal(auth));
    }

    @PutMapping("/{userId}/roles")
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'USER_REALM_ROLE_ASSIGN')")
    public UserResponse updateRoles(
        @PathVariable UUID tenantId,
        @PathVariable String userId,
        @Valid @RequestBody UpdateUserRolesRequest req,
        Authentication auth
    ) {
        return service.updateRoles(tenantId, userId, req.roles(), principal(auth));
    }

    @PostMapping("/{userId}/invite")
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'USER_INVITE')")
    @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
    public void resendInvite(@PathVariable UUID tenantId, @PathVariable String userId,
                              Authentication auth) {
        service.resendInvite(tenantId, userId, principal(auth));
    }

    /**
     * Marks the user's email verified (PUTs {@code emailVerified=true} on the
     * KC user). Gated by USER_INVITE: this is part of the invite/activation
     * lifecycle — the brokered invite path (same permission) already performs
     * the identical KC mutation.
     */
    @PostMapping("/{userId}/verify-email")
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'USER_INVITE')")
    @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
    public void verifyEmail(@PathVariable UUID tenantId, @PathVariable String userId,
                            Authentication auth) {
        service.verifyEmail(tenantId, userId, principal(auth));
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
