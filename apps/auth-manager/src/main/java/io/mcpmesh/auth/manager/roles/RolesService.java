package io.mcpmesh.auth.manager.roles;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.service.TenantService;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * "Custom Roles" backend for tenant admins. Composite roles live as KC realm
 * roles in the tenant realm; their constituents are atomic permissions
 * (client roles) on the per-app confidential client(s). Atomic permissions
 * themselves are defined by the dev via the access manifest and are read-only
 * here.
 *
 * <p>System clients (usermanagement, KC built-ins, the tenant's UI client)
 * are filtered out of the permissions catalog. System realm roles
 * (KC built-ins, anything tagged {@code system=true} via role attribute,
 * the reserved names listed in {@link #RESERVED_NAMES} / {@link #SYSTEM_NAME_PREFIX})
 * are filtered out of the composite-role list.
 */
@Service
public class RolesService {

    private static final Logger log = LoggerFactory.getLogger(RolesService.class);

    private static final ActorKind ACTOR_KIND = ActorKind.USER;

    /** OIDC clients that exist in every tenant realm but never hold app permissions. */
    private static final Set<String> SYSTEM_CLIENTS = Set.of(
        "usermanagement",
        "admin-cli",
        "account",
        "account-console",
        "broker",
        "realm-management",
        "security-admin-console"
    );

    /** KC built-in realm roles that must never appear in the composite-role list. */
    private static final Set<String> BUILTIN_REALM_ROLES = Set.of(
        "offline_access",
        "uma_authorization"
    );

    /**
     * KC-managed client-role names that get auto-created on an app's client
     * (e.g. when Authorization Services is enabled). Hidden from the
     * permissions catalog -- they're never user-assignable in the manifest sense.
     */
    private static final Set<String> SYSTEM_CLIENT_ROLES = Set.of(
        "uma_protection"
    );

    /**
     * Reserved composite-role names. Rejected at create/update time so admin
     * UI names can't collide with system identifiers.
     */
    private static final Set<String> RESERVED_NAMES = Set.of(
        "tenant-admin",
        "user-viewer"
    );

    private static final String SYSTEM_NAME_PREFIX = "_system";
    private static final String DEFAULT_ROLES_PREFIX = "default-roles-";

    /** Allowed characters in admin-facing composite-role names. */
    private static final Pattern NAME_PATTERN = Pattern.compile("^[A-Za-z0-9 _-]{1,50}$");

    /** Role attribute key: present + "true" means platform-managed. */
    private static final String SYSTEM_ATTR = "system";

    private final Keycloak admin;
    private final TenantService tenants;
    private final AuditService audit;

    public RolesService(Keycloak admin, TenantService tenants, AuditService audit) {
        this.admin = admin;
        this.tenants = tenants;
        this.audit = audit;
    }

    // -------------------------------------------------------------------------
    // Permissions catalog (read-only)
    // -------------------------------------------------------------------------

    public List<PermissionDto> listPermissions(String slug) {
        Tenant tenant = tenants.getBySlug(slug);
        RealmResource realm = admin.realm(tenant.getRealmName());

        // Tenant's UI client follows the {slug}-ui convention. Filter it out
        // alongside the well-known system clients so the permissions catalog
        // only shows actual app clients.
        String uiClient = slug + "-ui";

        List<PermissionDto> out = new ArrayList<>();
        for (ClientRepresentation client : realm.clients().findAll()) {
            String clientId = client.getClientId();
            if (clientId == null) continue;
            if (SYSTEM_CLIENTS.contains(clientId)) continue;
            if (clientId.equals(uiClient)) continue;

            ClientResource cr = realm.clients().get(client.getId());
            List<RoleRepresentation> roles;
            try {
                // List non-composite client roles only. Composite client roles
                // (rare in our manifest model) would be tenant-defined and we
                // don't expose those as atomic perms.
                roles = cr.roles().list();
            } catch (Exception e) {
                log.warn("Failed to list roles for client {} in realm {}: {}",
                    clientId, tenant.getRealmName(), e.getMessage());
                continue;
            }
            for (RoleRepresentation role : roles) {
                if (Boolean.TRUE.equals(role.isComposite())) continue;
                if (SYSTEM_CLIENT_ROLES.contains(role.getName())) continue;
                out.add(new PermissionDto(clientId, role.getName(), role.getDescription()));
            }
        }
        // Stable order so the UI lists permissions deterministically.
        out.sort((a, b) -> {
            int c = a.client().compareTo(b.client());
            return c != 0 ? c : a.name().compareTo(b.name());
        });
        return out;
    }

    // -------------------------------------------------------------------------
    // Composite-role CRUD
    // -------------------------------------------------------------------------

    public List<RoleDto> list(String slug) {
        Tenant tenant = tenants.getBySlug(slug);
        RealmResource realm = admin.realm(tenant.getRealmName());

        List<RoleRepresentation> allRoles = realm.roles().list();
        List<RoleDto> out = new ArrayList<>();
        for (RoleRepresentation r : allRoles) {
            if (!isVisibleComposite(r, tenant.getRealmName())) continue;
            out.add(toDto(realm, r));
        }
        out.sort((a, b) -> a.name().compareToIgnoreCase(b.name()));
        return out;
    }

    public RoleDto get(String slug, String roleName) {
        Tenant tenant = tenants.getBySlug(slug);
        RealmResource realm = admin.realm(tenant.getRealmName());
        RoleRepresentation r;
        try {
            r = realm.roles().get(roleName).toRepresentation();
        } catch (NotFoundException e) {
            throw new RoleNotFoundException(roleName);
        }
        if (!isVisibleComposite(r, tenant.getRealmName())) {
            throw new RoleNotFoundException(roleName);
        }
        return toDto(realm, r);
    }

    public RoleDto create(String slug, CreateRoleRequest req, String actor) {
        validateName(req.name());
        Tenant tenant = tenants.getBySlug(slug);
        RealmResource realm = admin.realm(tenant.getRealmName());

        // Fail fast if a role with that name already exists.
        try {
            realm.roles().get(req.name()).toRepresentation();
            throw new IllegalArgumentException("Role already exists: " + req.name());
        } catch (NotFoundException ignored) {
            // good -- not present
        }

        RoleRepresentation rep = new RoleRepresentation();
        rep.setName(req.name());
        rep.setDescription(req.description());
        rep.setComposite(true);

        try {
            realm.roles().create(rep);
            // KC create returns void; re-fetch to get the created representation
            // and to add composites.
            List<RoleRepresentation> composites = resolveComposites(realm, req.permissions());
            if (!composites.isEmpty()) {
                realm.roles().get(req.name()).addComposites(composites);
            }
        } catch (Exception e) {
            audit.recordFailure(actor, ACTOR_KIND, tenant.getId(),
                "role.create", "role", req.name(),
                req, e,
                Map.of("name", req.name(),
                       "permissionCount", req.permissions().size()));
            throw new RuntimeException("Role create failed: " + e.getMessage(), e);
        }

        audit.recordSuccess(actor, ACTOR_KIND, tenant.getId(),
            "role.create", "role", req.name(),
            req,
            Map.of("name", req.name(),
                   "description", req.description() == null ? "" : req.description(),
                   "permissionCount", req.permissions().size()));

        return get(slug, req.name());
    }

    public RoleDto update(String slug, String roleName, UpdateRoleRequest req, String actor) {
        validateName(roleName);
        Tenant tenant = tenants.getBySlug(slug);
        RealmResource realm = admin.realm(tenant.getRealmName());

        RoleResource rr = realm.roles().get(roleName);
        RoleRepresentation existing;
        try {
            existing = rr.toRepresentation();
        } catch (NotFoundException e) {
            throw new RoleNotFoundException(roleName);
        }
        if (!isVisibleComposite(existing, tenant.getRealmName())) {
            // Refuse to mutate system / hidden roles via this surface.
            throw new RoleNotFoundException(roleName);
        }

        try {
            existing.setDescription(req.description());
            existing.setComposite(true);
            rr.update(existing);

            // Diff composites.
            Set<RoleRepresentation> current = rr.getRoleComposites();
            List<RoleRepresentation> desired = resolveComposites(realm, req.permissions());

            Map<String, RoleRepresentation> currentByKey = current.stream()
                .filter(c -> c.getContainerId() != null)
                .collect(Collectors.toMap(RolesService::compositeKey, c -> c, (a, b) -> a));
            Map<String, RoleRepresentation> desiredByKey = desired.stream()
                .collect(Collectors.toMap(RolesService::compositeKey, c -> c, (a, b) -> a));

            List<RoleRepresentation> toAdd = new ArrayList<>();
            for (Map.Entry<String, RoleRepresentation> e : desiredByKey.entrySet()) {
                if (!currentByKey.containsKey(e.getKey())) toAdd.add(e.getValue());
            }
            List<RoleRepresentation> toRemove = new ArrayList<>();
            for (Map.Entry<String, RoleRepresentation> e : currentByKey.entrySet()) {
                if (!desiredByKey.containsKey(e.getKey())) toRemove.add(e.getValue());
            }
            if (!toRemove.isEmpty()) rr.deleteComposites(toRemove);
            if (!toAdd.isEmpty()) rr.addComposites(toAdd);
        } catch (RoleNotFoundException | IllegalArgumentException e) {
            audit.recordFailure(actor, ACTOR_KIND, tenant.getId(),
                "role.update", "role", roleName,
                req, e,
                Map.of("name", roleName));
            throw e;
        } catch (Exception e) {
            audit.recordFailure(actor, ACTOR_KIND, tenant.getId(),
                "role.update", "role", roleName,
                req, e,
                Map.of("name", roleName));
            throw new RuntimeException("Role update failed: " + e.getMessage(), e);
        }

        audit.recordSuccess(actor, ACTOR_KIND, tenant.getId(),
            "role.update", "role", roleName,
            req,
            Map.of("name", roleName,
                   "description", req.description() == null ? "" : req.description(),
                   "permissionCount", req.permissions().size()));

        return get(slug, roleName);
    }

    public void delete(String slug, String roleName, String actor) {
        Tenant tenant = tenants.getBySlug(slug);
        RealmResource realm = admin.realm(tenant.getRealmName());

        RoleResource rr = realm.roles().get(roleName);
        RoleRepresentation existing;
        try {
            existing = rr.toRepresentation();
        } catch (NotFoundException e) {
            throw new RoleNotFoundException(roleName);
        }
        if (!isVisibleComposite(existing, tenant.getRealmName())) {
            throw new RoleNotFoundException(roleName);
        }

        int userCount = safeUserCount(rr);
        if (userCount > 0) {
            audit.recordFailure(actor, ACTOR_KIND, tenant.getId(),
                "role.delete", "role", roleName,
                null,
                new RoleInUseException(roleName, userCount),
                Map.of("name", roleName, "userCount", userCount));
            throw new RoleInUseException(roleName, userCount);
        }

        try {
            realm.roles().deleteRole(roleName);
        } catch (Exception e) {
            audit.recordFailure(actor, ACTOR_KIND, tenant.getId(),
                "role.delete", "role", roleName,
                null, e,
                Map.of("name", roleName));
            throw new RuntimeException("Role delete failed: " + e.getMessage(), e);
        }

        audit.recordSuccess(actor, ACTOR_KIND, tenant.getId(),
            "role.delete", "role", roleName,
            null,
            Map.of("name", roleName));
    }

    // -------------------------------------------------------------------------
    // User <-> realm role assignment
    // -------------------------------------------------------------------------

    /** Current composite (manageable) realm-role names for a user. */
    public List<String> userManageableRealmRoles(String slug, String userId) {
        Tenant tenant = tenants.getBySlug(slug);
        RealmResource realm = admin.realm(tenant.getRealmName());
        var assigned = realm.users().get(userId).roles().realmLevel().listAll();
        Set<String> visible = currentVisibleRoleNames(realm, tenant.getRealmName());
        List<String> out = assigned.stream()
            .map(RoleRepresentation::getName)
            .filter(visible::contains)
            .sorted()
            .toList();
        return out;
    }

    public AssignResult updateUserRoles(String slug, String userId, List<String> desired, String actor) {
        Tenant tenant = tenants.getBySlug(slug);
        RealmResource realm = admin.realm(tenant.getRealmName());

        // Snapshot known visible roles (composite + non-system).
        Map<String, RoleRepresentation> visible = currentVisibleRoles(realm, tenant.getRealmName());

        // Reject unknown / system names up front so we never partially apply.
        Set<String> desiredSet = new LinkedHashMap<String, String>() {{
            for (String n : desired) put(n, n);
        }}.keySet();
        List<String> unknown = new ArrayList<>();
        for (String n : desiredSet) {
            if (!visible.containsKey(n)) unknown.add(n);
        }
        if (!unknown.isEmpty()) {
            throw new IllegalArgumentException(
                "Unknown or system role(s): " + String.join(",", unknown));
        }

        // Compute diff scoped to manageable roles only.
        var assigned = realm.users().get(userId).roles().realmLevel().listAll();
        Set<String> currentManageable = assigned.stream()
            .map(RoleRepresentation::getName)
            .filter(visible::containsKey)
            .collect(Collectors.toCollection(HashSet::new));

        List<String> toAdd = new ArrayList<>();
        for (String n : desiredSet) if (!currentManageable.contains(n)) toAdd.add(n);
        List<String> toRemove = new ArrayList<>();
        for (String n : currentManageable) if (!desiredSet.contains(n)) toRemove.add(n);

        try {
            if (!toRemove.isEmpty()) {
                List<RoleRepresentation> remRoles = toRemove.stream().map(visible::get).toList();
                realm.users().get(userId).roles().realmLevel().remove(remRoles);
            }
            if (!toAdd.isEmpty()) {
                List<RoleRepresentation> addRoles = toAdd.stream().map(visible::get).toList();
                realm.users().get(userId).roles().realmLevel().add(addRoles);
            }
        } catch (Exception e) {
            audit.recordFailure(actor, ACTOR_KIND, tenant.getId(),
                "user.role.update", "user", userId,
                Map.of("roleNames", desired), e,
                Map.of("userId", userId, "added", toAdd, "removed", toRemove));
            throw new RuntimeException("User role update failed: " + e.getMessage(), e);
        }

        audit.recordSuccess(actor, ACTOR_KIND, tenant.getId(),
            "user.role.update", "user", userId,
            Map.of("roleNames", desired),
            Map.of("userId", userId,
                   "addedRoles", toAdd,
                   "removedRoles", toRemove));

        return new AssignResult(toAdd, toRemove);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static void validateName(String name) {
        if (name == null || !NAME_PATTERN.matcher(name).matches()) {
            throw new IllegalArgumentException(
                "Invalid role name: must match [A-Za-z0-9 _-]{1,50}");
        }
        if (RESERVED_NAMES.contains(name)) {
            throw new IllegalArgumentException("Reserved role name: " + name);
        }
        if (name.startsWith(SYSTEM_NAME_PREFIX) || name.startsWith(DEFAULT_ROLES_PREFIX)) {
            throw new IllegalArgumentException("Reserved role name prefix: " + name);
        }
    }

    /** A realm role is a visible composite if it isn't built-in / default / system-tagged / reserved-named. */
    private boolean isVisibleComposite(RoleRepresentation r, String realmName) {
        String name = r.getName();
        if (name == null) return false;
        if (BUILTIN_REALM_ROLES.contains(name)) return false;
        if (name.startsWith(DEFAULT_ROLES_PREFIX)) return false;
        if (name.equals(DEFAULT_ROLES_PREFIX + realmName)) return false;
        if (name.startsWith(SYSTEM_NAME_PREFIX)) return false;
        if (RESERVED_NAMES.contains(name)) return false;
        Map<String, List<String>> attrs = r.getAttributes();
        if (attrs != null) {
            List<String> sys = attrs.get(SYSTEM_ATTR);
            if (sys != null && sys.stream().anyMatch("true"::equalsIgnoreCase)) return false;
        }
        return true;
    }

    /** Map of all manageable composite-role names -> their representation, used by the diff. */
    private Map<String, RoleRepresentation> currentVisibleRoles(RealmResource realm, String realmName) {
        Map<String, RoleRepresentation> out = new HashMap<>();
        for (RoleRepresentation r : realm.roles().list()) {
            if (isVisibleComposite(r, realmName)) out.put(r.getName(), r);
        }
        return out;
    }

    private Set<String> currentVisibleRoleNames(RealmResource realm, String realmName) {
        return currentVisibleRoles(realm, realmName).keySet();
    }

    private RoleDto toDto(RealmResource realm, RoleRepresentation r) {
        List<PermissionDto> perms = compositesAsPermissions(realm, r.getName());
        int userCount = safeUserCount(realm.roles().get(r.getName()));
        return new RoleDto(
            r.getName(),
            r.getDescription(),
            perms,
            userCount,
            false  // visible composites are by definition not system
        );
    }

    private List<PermissionDto> compositesAsPermissions(RealmResource realm, String roleName) {
        Set<RoleRepresentation> composites;
        try {
            composites = realm.roles().get(roleName).getRoleComposites();
        } catch (Exception e) {
            log.warn("Failed to fetch composites for role {}: {}", roleName, e.getMessage());
            return Collections.emptyList();
        }
        if (composites == null || composites.isEmpty()) return Collections.emptyList();

        // We only expose client-role constituents (not realm-role composites).
        // The composite RoleRepresentation has containerId == the KC client UUID
        // when it's a client role, == the realm name when it's a realm role.
        // Build a UUID -> clientId lookup once.
        Map<String, String> clientIdByUuid = new HashMap<>();
        for (ClientRepresentation c : realm.clients().findAll()) {
            clientIdByUuid.put(c.getId(), c.getClientId());
        }

        List<PermissionDto> out = new ArrayList<>();
        for (RoleRepresentation c : composites) {
            if (!Boolean.TRUE.equals(c.getClientRole())) continue;
            String containerId = c.getContainerId();
            String clientId = clientIdByUuid.get(containerId);
            if (clientId == null) {
                // Container UUID didn't match any client — stale; skip.
                continue;
            }
            out.add(new PermissionDto(clientId, c.getName(), c.getDescription()));
        }
        out.sort((a, b) -> {
            int cmp = a.client().compareTo(b.client());
            return cmp != 0 ? cmp : a.name().compareTo(b.name());
        });
        return out;
    }

    /**
     * Look up the {@link RoleRepresentation} for each {client, name} ref so
     * KC's {@code addComposites} call has the role's container id populated.
     * Throws {@link IllegalArgumentException} for any unknown ref.
     */
    private List<RoleRepresentation> resolveComposites(RealmResource realm,
                                                       List<CreateRoleRequest.PermissionRef> refs) {
        if (refs == null || refs.isEmpty()) return Collections.emptyList();
        Map<String, String> uuidByClientId = new HashMap<>();
        for (ClientRepresentation c : realm.clients().findAll()) {
            uuidByClientId.put(c.getClientId(), c.getId());
        }
        List<RoleRepresentation> out = new ArrayList<>(refs.size());
        for (CreateRoleRequest.PermissionRef ref : refs) {
            String clientUuid = uuidByClientId.get(ref.client());
            if (clientUuid == null) {
                throw new IllegalArgumentException(
                    "Unknown client in permissions: " + ref.client());
            }
            try {
                RoleRepresentation crep = realm.clients().get(clientUuid)
                    .roles().get(ref.name()).toRepresentation();
                out.add(crep);
            } catch (NotFoundException e) {
                throw new IllegalArgumentException(
                    "Unknown client role " + ref.client() + ":" + ref.name());
            }
        }
        return out;
    }

    /** Resilient user-count probe. KC throws on some role configs; treat as 0. */
    private int safeUserCount(RoleResource rr) {
        try {
            var members = rr.getRoleUserMembers();
            return members == null ? 0 : members.size();
        } catch (Exception e) {
            log.warn("getRoleUserMembers failed: {}", e.getMessage());
            return 0;
        }
    }

    private static String compositeKey(RoleRepresentation r) {
        return Objects.toString(r.getContainerId(), "") + "/" + r.getName();
    }

    public record AssignResult(List<String> added, List<String> removed) {}
}
