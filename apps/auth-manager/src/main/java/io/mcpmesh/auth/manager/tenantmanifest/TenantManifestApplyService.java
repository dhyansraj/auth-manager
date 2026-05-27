package io.mcpmesh.auth.manager.tenantmanifest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.IdentityProvidersBootstrap;
import io.mcpmesh.auth.manager.roles.CreateRoleRequest;
import io.mcpmesh.auth.manager.roles.RolesService;
import io.mcpmesh.auth.manager.roles.UpdateRoleRequest;
import io.mcpmesh.auth.manager.service.TenantService;
import jakarta.ws.rs.NotFoundException;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/**
 * Phase 2 write-side applier. Takes an incoming {@link TenantManifest} and
 * pushes additive changes into Keycloak:
 *
 * <ul>
 *   <li>Permissions (KC client roles on app clients) are created or have their
 *       description updated. Existing client roles not present in the manifest
 *       are <strong>never</strong> deleted; they surface as
 *       {@code skipped} with a warning.</li>
 *   <li>Composite roles (KC realm roles) follow the same rule when
 *       {@code applyRoles=true}, gated by a hash tripwire stored in the realm
 *       attribute {@link #SEED_ROLES_HASH_ATTR}.</li>
 * </ul>
 *
 * Role mutations are delegated to {@link RolesService} so audit + validation
 * stay in one place; permission mutations use the KC admin SDK directly
 * because the catalog is treated as read-only by {@link RolesService}.
 */
@Service
public class TenantManifestApplyService {

    private static final Logger log = LoggerFactory.getLogger(TenantManifestApplyService.class);

    /** Realm-attribute key holding the SHA-256 of the last-applied role set. */
    public static final String SEED_ROLES_HASH_ATTR = "mcpmesh_seed_roles_hash";

    private final Keycloak admin;
    private final TenantService tenants;
    private final TenantManifestService manifestService;
    private final RolesService rolesService;
    @Nullable private final IdentityProvidersBootstrap idps;
    private final ObjectMapper canonicalJson;

    @Autowired
    public TenantManifestApplyService(Keycloak admin,
                                      TenantService tenants,
                                      TenantManifestService manifestService,
                                      RolesService rolesService,
                                      @Nullable IdentityProvidersBootstrap idps) {
        this.admin = admin;
        this.tenants = tenants;
        this.manifestService = manifestService;
        this.rolesService = rolesService;
        this.idps = idps;
        // Canonical JSON for hashing: stable key order, no whitespace.
        this.canonicalJson = new ObjectMapper()
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            .disable(SerializationFeature.INDENT_OUTPUT);
    }

    /** Back-compat constructor for existing tests that don't exercise IdP/defaultRoles wiring. */
    public TenantManifestApplyService(Keycloak admin,
                                      TenantService tenants,
                                      TenantManifestService manifestService,
                                      RolesService rolesService) {
        this(admin, tenants, manifestService, rolesService, null);
    }

    /**
     * @throws TripwireException     when {@code applyRoles=true} and the
     *                               stored hash doesn't match the current KC
     *                               state and {@code force=false}. The
     *                               controller maps this to HTTP 409.
     * @throws IllegalArgumentException for validation failures (unknown client,
     *                               dangling permission reference). Maps to 400.
     */
    public ApplyResult apply(String slug, TenantManifest incoming,
                             boolean applyRoles, boolean force, boolean dryRun,
                             String actor) {
        Tenant tenant = tenants.getBySlug(slug);
        String realmName = tenant.getRealmName();

        // Snapshot KC's current state through the same code the GET endpoint
        // uses — guarantees the diff sees what the operator just inspected.
        TenantManifest current = manifestService.generate(slug);

        // -- 1. Validate manifest references against KC's live client + role state.
        validate(realmName, incoming, current);

        // -- 2. Permission diff (always computed).
        Map<String, TenantManifest.PermissionEntry> currentPermsById = byPermissionId(current.permissions());
        Map<String, TenantManifest.PermissionEntry> incomingPermsById = byPermissionId(safe(incoming.permissions()));

        List<String> permCreated = new ArrayList<>();
        List<String> permUpdated = new ArrayList<>();
        List<String> permUnchanged = new ArrayList<>();
        List<String> permSkipped = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        for (TenantManifest.PermissionEntry p : sortedById(incomingPermsById.values())) {
            TenantManifest.PermissionEntry existing = currentPermsById.get(p.id());
            if (existing == null) {
                permCreated.add(p.id());
            } else if (!Objects.equals(existing.description(), p.description())) {
                permUpdated.add(p.id());
            } else {
                permUnchanged.add(p.id());
            }
        }
        for (TenantManifest.PermissionEntry p : sortedById(currentPermsById.values())) {
            if (!incomingPermsById.containsKey(p.id())) {
                permSkipped.add(p.id());
                warnings.add("permission '" + p.id()
                    + "' exists in Keycloak but not in manifest; left alone");
            }
        }
        ApplyResult.Diff permDiff = new ApplyResult.Diff(
            permCreated, permUpdated, permUnchanged, permSkipped);

        // -- 3. (Optional) role diff + hash tripwire.
        ApplyResult.Diff roleDiff = null;
        ApplyResult.HashTripwireResult tripwire = null;
        Map<String, TenantManifest.RoleEntry> currentRolesByName = byRoleName(current.roles());
        Map<String, TenantManifest.RoleEntry> incomingRolesByName = applyRoles
            ? byRoleName(safe(incoming.roles())) : Map.of();

        // Permission lookup map (incoming wins over current — the manifest is
        // the source of truth for "what client owns this permission").
        Map<String, String> clientByPermId = new HashMap<>();
        for (TenantManifest.PermissionEntry p : currentPermsById.values()) {
            clientByPermId.put(p.id(), p.client());
        }
        for (TenantManifest.PermissionEntry p : incomingPermsById.values()) {
            clientByPermId.put(p.id(), p.client());
        }

        if (applyRoles) {
            String storedHash = readStoredHash(realmName);
            String currentHash = hashRoles(current.roles());
            boolean match = storedHash == null || storedHash.equals(currentHash);
            boolean tripped = !match && !force;

            if (tripped) {
                tripwire = new ApplyResult.HashTripwireResult(
                    storedHash, currentHash, false, true, null);
                throw new TripwireException(new ApplyResult(
                    dryRun, permDiff, ApplyResult.Diff.empty(), null, null, tripwire,
                    List.copyOf(warnings)));
            }

            // Compute role diff.
            List<String> roleCreated = new ArrayList<>();
            List<String> roleUpdated = new ArrayList<>();
            List<String> roleUnchanged = new ArrayList<>();
            List<String> roleSkipped = new ArrayList<>();

            for (TenantManifest.RoleEntry r : sortedByName(incomingRolesByName.values())) {
                TenantManifest.RoleEntry existing = currentRolesByName.get(r.name());
                if (existing == null) {
                    roleCreated.add(r.name());
                } else if (rolesDiffer(existing, r)) {
                    roleUpdated.add(r.name());
                } else {
                    roleUnchanged.add(r.name());
                }
            }
            for (TenantManifest.RoleEntry r : sortedByName(currentRolesByName.values())) {
                if (!incomingRolesByName.containsKey(r.name())) {
                    roleSkipped.add(r.name());
                    warnings.add("role '" + r.name()
                        + "' exists in Keycloak but not in manifest; left alone");
                }
            }
            roleDiff = new ApplyResult.Diff(
                roleCreated, roleUpdated, roleUnchanged, roleSkipped);

            tripwire = new ApplyResult.HashTripwireResult(
                storedHash, currentHash, match, !match /* tripped only meaningful with !force */,
                null);
        }

        // -- 3b. (Optional) identityProviders + defaultRoles diff.
        ApplyResult.Diff idpDiff = null;
        ApplyResult.Diff defaultRoleMappersDiff = null;

        Set<String> currentEnabledIdps = current.identityProviders() == null
            ? Set.of()
            : current.identityProviders().stream()
                .map(TenantManifest.IdentityProviderEntry::id)
                .filter(Objects::nonNull)
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));

        if (incoming.identityProviders() != null) {
            idpDiff = computeIdpDiff(incoming.identityProviders(), current.identityProviders());
        }

        if (incoming.defaultRoles() != null) {
            // Validate referenced role names: must exist in current state OR be
            // about to be created via the same apply's roles section.
            Set<String> knownRoleNames = new HashSet<>();
            for (TenantManifest.RoleEntry r : safe(current.roles())) knownRoleNames.add(r.name());
            if (applyRoles) {
                for (TenantManifest.RoleEntry r : safe(incoming.roles())) knownRoleNames.add(r.name());
            }

            List<String> listedRoles = new ArrayList<>();
            for (String name : incoming.defaultRoles()) {
                if (name == null || name.isBlank()) continue;
                if (!knownRoleNames.contains(name)) {
                    warnings.add("defaultRoles references unknown role '" + name + "' - skipped");
                    continue;
                }
                listedRoles.add(name);
            }

            // Set of IdPs to wire mappers on: union of currently-enabled and
            // those being enabled in this apply.
            Set<String> targetIdps = new LinkedHashSet<>(currentEnabledIdps);
            if (incoming.identityProviders() != null) {
                for (TenantManifest.IdentityProviderEntry e : incoming.identityProviders()) {
                    if (e == null || e.id() == null) continue;
                    if (Boolean.FALSE.equals(e.enabled())) {
                        targetIdps.remove(e.id());
                    } else {
                        targetIdps.add(e.id());
                    }
                }
            }

            defaultRoleMappersDiff = computeDefaultRoleMappersDiff(
                realmName, targetIdps, listedRoles);
        }

        // -- 4. Execute (skip on dryRun).
        if (!dryRun) {
            applyPermissionMutations(realmName, permCreated, permUpdated, incomingPermsById);

            if (applyRoles) {
                applyRoleMutations(slug, roleDiff, incomingRolesByName, clientByPermId, actor);

                // Recompute hash from KC's NEW state and persist.
                TenantManifest postApply = manifestService.generate(slug);
                String newHash = hashRoles(postApply.roles());
                writeStoredHash(realmName, newHash);
                tripwire = new ApplyResult.HashTripwireResult(
                    tripwire.storedHash(),
                    tripwire.currentHash(),
                    tripwire.match(),
                    tripwire.match() ? false : true,
                    newHash);
            }

            // 4a: IdP reconciliation (enable first so 4b's mappers attach to live IdPs).
            if (incoming.identityProviders() != null) {
                applyIdpMutations(realmName, incoming.identityProviders());
            }

            // 4b: defaultRoles -> Hardcoded Role mappers.
            if (incoming.defaultRoles() != null && defaultRoleMappersDiff != null) {
                applyDefaultRoleMapperMutations(realmName, defaultRoleMappersDiff);
            }
        }

        return new ApplyResult(
            dryRun, permDiff, roleDiff, idpDiff, defaultRoleMappersDiff,
            tripwire, List.copyOf(warnings));
    }

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    private void validate(String realmName, TenantManifest incoming, TenantManifest current) {
        // Build the set of clientIds that actually exist in KC (defensive against
        // typos / drift). Cheap because we already need this for execution.
        RealmResource realm = admin.realm(realmName);
        Set<String> kcClientIds = new HashSet<>();
        for (ClientRepresentation c : realm.clients().findAll()) {
            if (c.getClientId() != null) kcClientIds.add(c.getClientId());
        }

        // 1. Every permission must reference a real client.
        for (TenantManifest.PermissionEntry p : safe(incoming.permissions())) {
            if (p.client() == null || p.client().isBlank()) {
                throw new IllegalArgumentException(
                    "Permission '" + p.id() + "' is missing a client");
            }
            if (!kcClientIds.contains(p.client())) {
                throw new IllegalArgumentException(
                    "Permission '" + p.id() + "' references unknown client '"
                        + p.client() + "'");
            }
        }

        // 2. Role permission ids must resolve in the manifest OR the current KC state.
        Set<String> knownPermIds = new HashSet<>();
        for (TenantManifest.PermissionEntry p : safe(incoming.permissions())) knownPermIds.add(p.id());
        for (TenantManifest.PermissionEntry p : safe(current.permissions())) knownPermIds.add(p.id());

        for (TenantManifest.RoleEntry r : safe(incoming.roles())) {
            for (String permId : safe(r.permissions())) {
                if (!knownPermIds.contains(permId)) {
                    throw new IllegalArgumentException(
                        "Role '" + r.name() + "' references unknown permission '"
                            + permId + "'");
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Execution — permissions (direct KC admin SDK)
    // -------------------------------------------------------------------------

    private void applyPermissionMutations(String realmName,
                                          List<String> toCreate,
                                          List<String> toUpdate,
                                          Map<String, TenantManifest.PermissionEntry> incomingPermsById) {
        if (toCreate.isEmpty() && toUpdate.isEmpty()) return;

        RealmResource realm = admin.realm(realmName);
        // clientId -> KC UUID (built once, reused for every mutation).
        Map<String, String> uuidByClientId = new HashMap<>();
        for (ClientRepresentation c : realm.clients().findAll()) {
            uuidByClientId.put(c.getClientId(), c.getId());
        }

        for (String permId : toCreate) {
            TenantManifest.PermissionEntry p = incomingPermsById.get(permId);
            String clientUuid = uuidByClientId.get(p.client());
            if (clientUuid == null) {
                // Already caught by validate(), but defensive.
                throw new IllegalArgumentException(
                    "Client '" + p.client() + "' not found while creating permission '"
                        + permId + "'");
            }
            ClientResource cr = realm.clients().get(clientUuid);
            RoleRepresentation role = new RoleRepresentation();
            role.setName(p.id());
            role.setDescription(p.description());
            cr.roles().create(role);
            log.info("Created client role {}:{} in realm {}", p.client(), p.id(), realmName);
        }

        for (String permId : toUpdate) {
            TenantManifest.PermissionEntry p = incomingPermsById.get(permId);
            String clientUuid = uuidByClientId.get(p.client());
            if (clientUuid == null) {
                throw new IllegalArgumentException(
                    "Client '" + p.client() + "' not found while updating permission '"
                        + permId + "'");
            }
            ClientResource cr = realm.clients().get(clientUuid);
            RoleRepresentation existing;
            try {
                existing = cr.roles().get(p.id()).toRepresentation();
            } catch (NotFoundException e) {
                // Drifted between snapshot and execute — create instead.
                RoleRepresentation role = new RoleRepresentation();
                role.setName(p.id());
                role.setDescription(p.description());
                cr.roles().create(role);
                log.info("Created (was missing on update) client role {}:{} in realm {}",
                    p.client(), p.id(), realmName);
                continue;
            }
            existing.setDescription(p.description());
            cr.roles().get(p.id()).update(existing);
            log.info("Updated client role {}:{} in realm {}", p.client(), p.id(), realmName);
        }
    }

    // -------------------------------------------------------------------------
    // Execution — roles (delegated to RolesService)
    // -------------------------------------------------------------------------

    private void applyRoleMutations(String slug, ApplyResult.Diff roleDiff,
                                    Map<String, TenantManifest.RoleEntry> incomingRolesByName,
                                    Map<String, String> clientByPermId,
                                    String actor) {
        for (String name : roleDiff.created()) {
            TenantManifest.RoleEntry r = incomingRolesByName.get(name);
            CreateRoleRequest req = new CreateRoleRequest(
                r.name(), r.description(), toPermissionRefs(r.permissions(), clientByPermId));
            rolesService.create(slug, req, actor);
        }
        for (String name : roleDiff.updated()) {
            TenantManifest.RoleEntry r = incomingRolesByName.get(name);
            UpdateRoleRequest req = new UpdateRoleRequest(
                r.description(), toPermissionRefs(r.permissions(), clientByPermId));
            rolesService.update(slug, r.name(), req, actor);
        }
    }

    private static List<CreateRoleRequest.PermissionRef> toPermissionRefs(
        List<String> permIds, Map<String, String> clientByPermId) {
        List<CreateRoleRequest.PermissionRef> out = new ArrayList<>();
        for (String id : safe(permIds)) {
            String client = clientByPermId.get(id);
            if (client == null) {
                // Validation already passed; if we reach here KC drifted under us.
                throw new IllegalStateException(
                    "Cannot resolve owning client for permission '" + id + "'");
            }
            out.add(new CreateRoleRequest.PermissionRef(client, id));
        }
        return out;
    }

    // -------------------------------------------------------------------------
    // IdP + defaultRoles diff + execution
    // -------------------------------------------------------------------------

    private ApplyResult.Diff computeIdpDiff(
        List<TenantManifest.IdentityProviderEntry> incoming,
        List<TenantManifest.IdentityProviderEntry> current
    ) {
        Map<String, Boolean> currentById = new HashMap<>();
        for (TenantManifest.IdentityProviderEntry e : safe(current)) {
            if (e.id() != null) currentById.put(e.id(), e.enabled());
        }
        List<String> created = new ArrayList<>();
        List<String> updated = new ArrayList<>();
        List<String> unchanged = new ArrayList<>();
        List<String> skipped = new ArrayList<>();

        Set<String> incomingIds = new LinkedHashSet<>();
        for (TenantManifest.IdentityProviderEntry e : incoming) {
            if (e == null || e.id() == null) continue;
            incomingIds.add(e.id());
            boolean wantEnabled = !Boolean.FALSE.equals(e.enabled());
            if (!currentById.containsKey(e.id())) {
                if (wantEnabled) {
                    created.add(e.id());
                }
                // explicit enabled=false on a missing IdP is a no-op
            } else {
                Boolean curEnabled = currentById.get(e.id());
                boolean curIsEnabled = !Boolean.FALSE.equals(curEnabled);
                if (curIsEnabled == wantEnabled) {
                    unchanged.add(e.id());
                } else {
                    updated.add(e.id());
                }
            }
        }
        for (String existing : currentById.keySet()) {
            if (!incomingIds.contains(existing)) skipped.add(existing);
        }
        created.sort(Comparator.naturalOrder());
        updated.sort(Comparator.naturalOrder());
        unchanged.sort(Comparator.naturalOrder());
        skipped.sort(Comparator.naturalOrder());
        return new ApplyResult.Diff(created, updated, unchanged, skipped);
    }

    private ApplyResult.Diff computeDefaultRoleMappersDiff(
        String realmName, Set<String> targetIdps, List<String> listedRoles
    ) {
        // Mapper sections are authoritative: existing IdP roles NOT in the
        // manifest's defaultRoles list are deleted (see
        // applyDefaultRoleMapperMutations). That makes them `deleted`, not
        // `skipped` — `skipped` means "left untouched".
        List<String> created = new ArrayList<>();
        List<String> unchanged = new ArrayList<>();
        List<String> deleted = new ArrayList<>();
        Set<String> listedSet = new LinkedHashSet<>(listedRoles);

        for (String idp : targetIdps) {
            Set<String> existing = (idps == null) ? Set.of() : idps.listHardcodedRoles(realmName, idp);
            for (String role : listedRoles) {
                String label = idp + ":" + role;
                if (existing.contains(role)) {
                    unchanged.add(label);
                } else {
                    created.add(label);
                }
            }
            for (String existingRole : existing) {
                if (!listedSet.contains(existingRole)) {
                    deleted.add(idp + ":" + existingRole);
                }
            }
        }
        created.sort(Comparator.naturalOrder());
        unchanged.sort(Comparator.naturalOrder());
        deleted.sort(Comparator.naturalOrder());
        return new ApplyResult.Diff(created, List.of(), unchanged, List.of(), deleted);
    }

    private void applyIdpMutations(String realmName,
                                   List<TenantManifest.IdentityProviderEntry> incoming) {
        if (idps == null) {
            log.warn("applyIdpMutations: IdentityProvidersBootstrap not wired; skipping IdP reconciliation");
            return;
        }
        for (TenantManifest.IdentityProviderEntry entry : incoming) {
            if (entry == null || entry.id() == null) continue;
            try {
                if (Boolean.FALSE.equals(entry.enabled())) {
                    idps.removeProvider(realmName, entry.id());
                } else {
                    idps.ensureProviders(realmName, Set.of(entry.id()));
                }
            } catch (Exception e) {
                log.warn("applyIdpMutations: {} on '{}' failed: {}",
                    entry.id(), realmName, e.getMessage());
            }
        }
    }

    /**
     * Applies the previously-computed defaultRoleMappersDiff:
     * - created entries -> ensureHardcodedRoleMapper
     * - deleted entries (existing role NOT in the manifest's defaultRoles list)
     *   -> removeHardcodedRoleMapper (per spec: list is authoritative).
     * Diff "name" entries are formatted "<idp>:<role>".
     */
    private void applyDefaultRoleMapperMutations(String realmName, ApplyResult.Diff diff) {
        if (idps == null) {
            log.warn("applyDefaultRoleMapperMutations: IdentityProvidersBootstrap not wired; skipping");
            return;
        }
        for (String label : diff.created()) {
            String[] parts = label.split(":", 2);
            if (parts.length != 2) continue;
            try {
                idps.ensureHardcodedRoleMapper(realmName, parts[0], parts[1]);
            } catch (Exception e) {
                log.warn("ensureHardcodedRoleMapper({}, {}, {}) failed: {}",
                    realmName, parts[0], parts[1], e.getMessage());
            }
        }
        for (String label : diff.deleted()) {
            String[] parts = label.split(":", 2);
            if (parts.length != 2) continue;
            try {
                idps.removeHardcodedRoleMapper(realmName, parts[0], parts[1]);
            } catch (Exception e) {
                log.warn("removeHardcodedRoleMapper({}, {}, {}) failed: {}",
                    realmName, parts[0], parts[1], e.getMessage());
            }
        }
    }

    // -------------------------------------------------------------------------
    // Hash tripwire
    // -------------------------------------------------------------------------

    /** Public so tests can assert the algorithm independently of the apply flow. */
    public String hashRoles(List<TenantManifest.RoleEntry> roles) {
        // Build canonical structure: each role -> { name, permissions: [<client>/<id>...] }
        // (We don't have client info here for the role's permissions on its own
        // — but the role names in the manifest are atomic ids; we'd need the
        // client lookup. For the hash we use the ID alone, which is enough to
        // detect role-content drift in practice.)
        //
        // Simpler + deterministic: hash { name, permissions: [<id>...] } with
        // both lists sorted. Descriptions are NOT included (documentation, not
        // authz state, per spec).
        List<Map<String, Object>> canonical = new ArrayList<>();
        for (TenantManifest.RoleEntry r : safe(roles)) {
            List<String> perms = new ArrayList<>(safe(r.permissions()));
            perms.sort(Comparator.naturalOrder());
            Map<String, Object> entry = new TreeMap<>();
            entry.put("name", r.name());
            entry.put("permissions", perms);
            canonical.add(entry);
        }
        canonical.sort(Comparator.comparing(m -> (String) m.get("name")));
        try {
            byte[] bytes = canonicalJson.writeValueAsBytes(canonical);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return "sha256:" + HexFormat.of().formatHex(md.digest(bytes));
        } catch (JsonProcessingException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to compute role-set hash", e);
        }
    }

    private String readStoredHash(String realmName) {
        RealmRepresentation rep = admin.realm(realmName).toRepresentation();
        Map<String, String> attrs = rep.getAttributes();
        if (attrs == null) return null;
        return attrs.get(SEED_ROLES_HASH_ATTR);
    }

    private void writeStoredHash(String realmName, String hash) {
        RealmRepresentation rep = admin.realm(realmName).toRepresentation();
        Map<String, String> attrs = rep.getAttributes();
        if (attrs == null) {
            attrs = new HashMap<>();
        }
        attrs.put(SEED_ROLES_HASH_ATTR, hash);
        rep.setAttributes(attrs);
        admin.realm(realmName).update(rep);
    }

    // -------------------------------------------------------------------------
    // Small helpers
    // -------------------------------------------------------------------------

    private static <T> List<T> safe(List<T> in) {
        return in == null ? List.of() : in;
    }

    private static Map<String, TenantManifest.PermissionEntry> byPermissionId(
        Iterable<TenantManifest.PermissionEntry> entries) {
        Map<String, TenantManifest.PermissionEntry> out = new HashMap<>();
        for (TenantManifest.PermissionEntry p : entries) out.put(p.id(), p);
        return out;
    }

    private static Map<String, TenantManifest.RoleEntry> byRoleName(
        Iterable<TenantManifest.RoleEntry> entries) {
        Map<String, TenantManifest.RoleEntry> out = new HashMap<>();
        for (TenantManifest.RoleEntry r : entries) out.put(r.name(), r);
        return out;
    }

    private static List<TenantManifest.PermissionEntry> sortedById(
        Iterable<TenantManifest.PermissionEntry> in) {
        List<TenantManifest.PermissionEntry> out = new ArrayList<>();
        in.forEach(out::add);
        out.sort(Comparator.comparing(TenantManifest.PermissionEntry::id));
        return out;
    }

    private static List<TenantManifest.RoleEntry> sortedByName(
        Iterable<TenantManifest.RoleEntry> in) {
        List<TenantManifest.RoleEntry> out = new ArrayList<>();
        in.forEach(out::add);
        out.sort(Comparator.comparing(TenantManifest.RoleEntry::name));
        return out;
    }

    private static boolean rolesDiffer(TenantManifest.RoleEntry a, TenantManifest.RoleEntry b) {
        if (!Objects.equals(a.description(), b.description())) return true;
        List<String> ap = new ArrayList<>(safe(a.permissions()));
        List<String> bp = new ArrayList<>(safe(b.permissions()));
        ap.sort(Comparator.naturalOrder());
        bp.sort(Comparator.naturalOrder());
        return !ap.equals(bp);
    }

    /**
     * Signals the hash-tripwire fired with {@code force=false}. Carries the
     * partially-populated {@link ApplyResult} so the controller can return
     * HTTP 409 with the {@code HashTripwireResult} in the body.
     */
    public static class TripwireException extends RuntimeException {
        private final ApplyResult result;

        public TripwireException(ApplyResult result) {
            super("Stored role-set hash does not match current Keycloak state. "
                + "Re-export the manifest, reconcile, and retry with force=true.");
            this.result = result;
        }

        public ApplyResult result() {
            return result;
        }
    }
}
