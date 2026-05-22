package io.mcpmesh.auth.manager.service;

import io.mcpmesh.auth.manager.api.dto.CreateUserRequest;
import io.mcpmesh.auth.manager.api.dto.UserResponse;
import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
@Transactional
public class UserManagementService {

    private static final Logger log = LoggerFactory.getLogger(UserManagementService.class);
    private static final ActorKind ACTOR_KIND = ActorKind.USER;
    private static final String USERMANAGEMENT_CLIENT = "usermanagement";
    /**
     * Baseline role granted to every active user in a tenant realm. Required so
     * a user can view their own profile. Always added to the effective role
     * set on create / update, even if the caller omits it.
     */
    private static final String BASELINE_ROLE = "user-viewer";

    private final TenantService tenants;
    private final KeycloakAdminService keycloak;
    private final AuditService audit;

    public UserManagementService(TenantService tenants, KeycloakAdminService keycloak, AuditService audit) {
        this.tenants = tenants;
        this.keycloak = keycloak;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public ListResult list(UUID tenantId, String search, int first, int max) {
        Tenant t = tenants.get(tenantId);
        var users = keycloak.listUsers(t.getRealmName(), search, first, max);
        int total = keycloak.countUsers(t.getRealmName(), search);
        var responses = users.stream()
            .map(u -> UserResponse.from(u, keycloak.getUserClientRoles(t.getRealmName(), u.getId(), USERMANAGEMENT_CLIENT)))
            .toList();
        return new ListResult(responses, first, max, total);
    }

    @Transactional(readOnly = true)
    public UserResponse get(UUID tenantId, String userId) {
        Tenant t = tenants.get(tenantId);
        UserRepresentation u = keycloak.getUser(t.getRealmName(), userId);
        var roles = keycloak.getUserClientRoles(t.getRealmName(), userId, USERMANAGEMENT_CLIENT);
        return UserResponse.from(u, roles);
    }

    public UserResponse create(UUID tenantId, CreateUserRequest req, String actor) {
        Tenant t = tenants.get(tenantId);
        // Validate caller-supplied roles first (may be null), then ensure the
        // baseline user-viewer role is always part of the effective set so
        // every user can view their own profile. tenant-admin (if requested)
        // is layered on top.
        List<String> requested = req.roles() == null ? List.of() : req.roles();
        validateRoles(requested);
        Set<String> rolesToAssign = new java.util.LinkedHashSet<>();
        rolesToAssign.add(BASELINE_ROLE);
        rolesToAssign.addAll(requested);

        String userId;
        try {
            userId = keycloak.createUser(t.getRealmName(), req.email(), req.email(),
                req.firstName(), req.lastName());
            for (String role : rolesToAssign) {
                keycloak.assignClientRoleToUser(t.getRealmName(), userId, USERMANAGEMENT_CLIENT, role);
            }
            boolean sendInvite = req.sendInvite() == null ? true : req.sendInvite();
            if (sendInvite) {
                try {
                    keycloak.sendExecuteActionsEmail(t.getRealmName(), userId,
                        List.of("UPDATE_PASSWORD"), 86400);
                } catch (Exception e) {
                    log.warn("Failed to send invite email to {}: {}", req.email(), e.getMessage());
                }
            }
        } catch (Exception e) {
            audit.recordFailure(actor, ACTOR_KIND, tenantId,
                "user.create", "user", null,
                req, e, Map.of("email", req.email()));
            throw new RuntimeException("User create failed: " + e.getMessage(), e);
        }
        audit.recordSuccess(actor, ACTOR_KIND, tenantId,
            "user.create", "user", userId,
            req, Map.of("email", req.email(), "roles", rolesToAssign));
        return get(tenantId, userId);
    }

    public void disable(UUID tenantId, String userId, String actor) {
        Tenant t = tenants.get(tenantId);
        keycloak.disableUser(t.getRealmName(), userId);
        audit.recordSuccess(actor, ACTOR_KIND, tenantId,
            "user.disable", "user", userId, null, Map.of());
    }

    public UserResponse updateRoles(UUID tenantId, String userId, Set<String> desiredRoles, String actor) {
        validateRoles(desiredRoles);
        // user-viewer is an invariant on every active user. If the caller
        // omits it we silently re-add it rather than 400, since the intent is
        // "set my role mix to X" — we satisfy that by also keeping the baseline.
        Set<String> effective = new HashSet<>(desiredRoles);
        effective.add(BASELINE_ROLE);
        Tenant t = tenants.get(tenantId);

        Set<String> current = new HashSet<>(keycloak.getUserClientRoles(t.getRealmName(), userId, USERMANAGEMENT_CLIENT));
        Set<String> toAdd    = new HashSet<>(effective); toAdd.removeAll(current);
        Set<String> toRemove = new HashSet<>(current);   toRemove.removeAll(effective);

        for (String r : toAdd) keycloak.assignClientRoleToUser(t.getRealmName(), userId, USERMANAGEMENT_CLIENT, r);
        for (String r : toRemove) keycloak.removeClientRoleFromUser(t.getRealmName(), userId, USERMANAGEMENT_CLIENT, r);

        audit.recordSuccess(actor, ACTOR_KIND, tenantId,
            "user.roles.update", "user", userId,
            desiredRoles, Map.of("added", toAdd, "removed", toRemove));
        return get(tenantId, userId);
    }

    public void resendInvite(UUID tenantId, String userId, String actor) {
        Tenant t = tenants.get(tenantId);
        keycloak.sendExecuteActionsEmail(t.getRealmName(), userId, List.of("UPDATE_PASSWORD"), 86400);
        audit.recordSuccess(actor, ACTOR_KIND, tenantId,
            "user.invite.resend", "user", userId, null, Map.of());
    }

    private void validateRoles(java.util.Collection<String> roles) {
        for (String r : roles) {
            if (!CreateUserRequest.ALLOWED_ROLES.contains(r)) {
                throw new IllegalArgumentException("Role not allowed: " + r);
            }
        }
    }

    public record ListResult(List<UserResponse> items, int first, int max, int totalItems) {}
}
