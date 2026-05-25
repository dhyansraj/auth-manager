package io.mcpmesh.auth.manager.tenantmanifest;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.roles.PermissionDto;
import io.mcpmesh.auth.manager.roles.RoleDto;
import io.mcpmesh.auth.manager.roles.RolesService;
import io.mcpmesh.auth.manager.service.TenantService;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Phase 1 read-only assembler: combines the tenant's permissions catalog and
 * composite roles into a single {@link TenantManifest} payload suitable for
 * YAML export. The output is sorted deterministically so that re-exports
 * produce stable diffs.
 *
 * <p>Also reads the realm's brokered IdPs and any Hardcoded-Role IdP mappers
 * (the source for the manifest's {@code defaultRoles} field). The mapper set
 * is UNIONed across all enabled IdPs; drift between IdPs is logged as a
 * warning but never fails generation.
 */
@Service
public class TenantManifestService {

    private static final Logger log = LoggerFactory.getLogger(TenantManifestService.class);

    static final String MANIFEST_VERSION = "v1";

    private static final String HARDCODED_ROLE_MAPPER_ID = "oidc-hardcoded-role-idp-mapper";

    private final RolesService rolesService;
    private final TenantService tenants;
    @Nullable private final Keycloak admin;

    @Autowired
    public TenantManifestService(RolesService rolesService,
                                 TenantService tenants,
                                 @Nullable Keycloak admin) {
        this.rolesService = rolesService;
        this.tenants = tenants;
        this.admin = admin;
    }

    /** Back-compat constructor used by existing unit tests that don't need KC IdP reads. */
    public TenantManifestService(RolesService rolesService, TenantService tenants) {
        this(rolesService, tenants, null);
    }

    public TenantManifest generate(String slug) {
        Tenant tenant = tenants.getBySlug(slug);
        String realmName = tenant.getRealmName();

        List<TenantManifest.PermissionEntry> permissions =
            rolesService.listPermissions(slug).stream()
                .map(TenantManifestService::toPermissionEntry)
                .sorted(Comparator.comparing(TenantManifest.PermissionEntry::id))
                .toList();

        List<TenantManifest.RoleEntry> roles =
            rolesService.list(slug).stream()
                .map(TenantManifestService::toRoleEntry)
                .sorted(Comparator.comparing(TenantManifest.RoleEntry::name))
                .toList();

        List<TenantManifest.IdentityProviderEntry> idps = readIdentityProviders(realmName);
        List<String> defaultRoles = readDefaultRolesUnion(realmName, idps);

        TenantManifest.Meta meta = new TenantManifest.Meta(
            tenant.getSlug(),
            realmName,
            Instant.now(),
            MANIFEST_VERSION
        );

        return new TenantManifest(meta, permissions, roles, idps, defaultRoles);
    }

    private List<TenantManifest.IdentityProviderEntry> readIdentityProviders(String realmName) {
        if (admin == null || realmName == null) return List.of();
        try {
            List<IdentityProviderRepresentation> reps =
                admin.realm(realmName).identityProviders().findAll();
            List<TenantManifest.IdentityProviderEntry> out = new ArrayList<>();
            for (IdentityProviderRepresentation r : reps) {
                out.add(new TenantManifest.IdentityProviderEntry(r.getAlias(), r.isEnabled()));
            }
            out.sort(Comparator.comparing(
                TenantManifest.IdentityProviderEntry::id,
                Comparator.nullsLast(Comparator.naturalOrder())));
            return out;
        } catch (Exception e) {
            log.warn("readIdentityProviders({}) failed: {}", realmName, e.getMessage());
            return List.of();
        }
    }

    /**
     * UNION of Hardcoded Realm Role IdP mapper role-names across every enabled
     * IdP on the realm. If different IdPs assign different sets of hardcoded
     * roles, the union is still returned but a warning is logged describing
     * the drift.
     */
    private List<String> readDefaultRolesUnion(String realmName,
                                               List<TenantManifest.IdentityProviderEntry> idps) {
        if (admin == null || realmName == null || idps.isEmpty()) return List.of();
        Map<String, Set<String>> rolesByIdp = new LinkedHashMap<>();
        Set<String> union = new TreeSet<>();
        for (TenantManifest.IdentityProviderEntry entry : idps) {
            if (entry.id() == null) continue;
            if (Boolean.FALSE.equals(entry.enabled())) continue;
            Set<String> roles = readHardcodedRoles(realmName, entry.id());
            rolesByIdp.put(entry.id(), roles);
            union.addAll(roles);
        }
        if (rolesByIdp.size() > 1) {
            Set<String> first = null;
            boolean drift = false;
            for (Set<String> s : rolesByIdp.values()) {
                if (first == null) {
                    first = s;
                } else if (!first.equals(s)) {
                    drift = true;
                    break;
                }
            }
            if (drift) {
                log.warn("defaultRoles drift between IdPs on realm {}: {} - manifest UNION is {}",
                    realmName, rolesByIdp, union);
            }
        }
        return new ArrayList<>(union);
    }

    private Set<String> readHardcodedRoles(String realmName, String alias) {
        try {
            List<IdentityProviderMapperRepresentation> mappers =
                admin.realm(realmName).identityProviders().get(alias).getMappers();
            Set<String> out = new TreeSet<>();
            for (IdentityProviderMapperRepresentation m : mappers) {
                if (HARDCODED_ROLE_MAPPER_ID.equals(m.getIdentityProviderMapper())
                    && m.getConfig() != null) {
                    String r = m.getConfig().get("role");
                    if (r != null && !r.isBlank()) out.add(r);
                }
            }
            return out;
        } catch (Exception e) {
            log.warn("readHardcodedRoles({}, {}) failed: {}", realmName, alias, e.getMessage());
            return Set.of();
        }
    }

    private static TenantManifest.PermissionEntry toPermissionEntry(PermissionDto p) {
        return new TenantManifest.PermissionEntry(p.name(), p.description(), p.client());
    }

    private static TenantManifest.RoleEntry toRoleEntry(RoleDto r) {
        List<String> permIds = r.permissions() == null ? List.of() :
            r.permissions().stream()
                .map(PermissionDto::name)
                .sorted()
                .toList();
        return new TenantManifest.RoleEntry(r.name(), r.description(), permIds);
    }
}
