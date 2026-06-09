package io.mcpmesh.auth.manager.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Canonical catalog of atomic permission strings used by the admin-ui to gate
 * menus, tabs, and actions. These names are stable contract: admin-ui Phase C
 * will reference them by exact string.
 *
 * <p>Two surfaces:
 * <ul>
 *   <li>{@link #PLATFORM_PERMS} -- platform-wide capabilities. Materialized as
 *       client roles on the {@code dev} realm's {@code usermanagement} client
 *       and bundled into the {@code platform-admin} realm role as composites.</li>
 *   <li>{@link #TENANT_CONFIG_PERMS} + {@link #TENANT_USER_MGMT_PERMS} +
 *       {@link #TENANT_SYSTEM_ROLE_PERM} -- per-tenant capabilities. Materialized
 *       as client roles on each tenant realm's {@code usermanagement} client and
 *       bundled into the {@code tenant-admin} / {@code tenant-user-manager}
 *       client roles as composites.</li>
 * </ul>
 *
 * <p>JWT delivery: KC's composite-role expansion flattens these into the
 * {@code resource_access.usermanagement.roles} claim automatically -- the same
 * mechanism we already rely on for the safesound manifest pattern.
 */
public final class PlatformPermissions {

    private PlatformPermissions() {}

    // ---- Platform-level (on `dev` realm's `usermanagement` client) ----

    public static final List<String> PLATFORM_PERMS = List.of(
        "TENANT_LIST_ALL",
        "TENANT_CREATE",
        "TENANT_DELETE",
        "GLOBAL_AUDIT_VIEW",
        "SYSTEM_CLIENT_MANAGE"
    );

    // ---- Tenant-level (on each tenant realm's `usermanagement` client) ----

    /**
     * Baseline perms required to even render the tenant detail page. Bundled
     * into BOTH {@code tenant-admin} AND {@code tenant-user-manager} since
     * the tenant detail GET endpoint gates on {@code TENANT_VIEW} and
     * tenant-user-manager users need to click into a tenant to manage its
     * users.
     */
    public static final List<String> TENANT_BASE_PERMS = List.of("TENANT_VIEW");

    /** Bundled into {@code tenant-admin} only. */
    public static final List<String> TENANT_CONFIG_PERMS = List.of(
        "TENANT_EDIT",
        "ROUTES_EDIT",
        "IDP_EDIT",
        "BRANDING_EDIT",
        "EMAIL_EDIT",
        "EMAIL_SEND",
        "PERMISSIONS_EDIT",
        "ROLES_EDIT",
        "APPS_EDIT",
        "MANIFEST_APPLY"
    );

    /** Bundled into BOTH {@code tenant-admin} AND {@code tenant-user-manager}. */
    public static final List<String> TENANT_USER_MGMT_PERMS = List.of(
        "USER_LIST",
        "USER_INVITE",
        "USER_DISABLE",
        "USER_REALM_ROLE_ASSIGN",
        "AUDIT_VIEW"
    );

    /**
     * Privileged: bundled into {@code tenant-admin} ONLY (NOT
     * {@code tenant-user-manager}). Gates privilege-escalation -- only
     * tenant-admin can promote a user to tenant-admin / tenant-user-manager.
     */
    public static final String TENANT_SYSTEM_ROLE_PERM = "USER_SYSTEM_ROLE_ASSIGN";

    /** Full bundle assigned to {@code tenant-admin} on each tenant realm. */
    public static final List<String> TENANT_ADMIN_BUNDLE = concat(
        TENANT_BASE_PERMS,
        TENANT_CONFIG_PERMS,
        TENANT_USER_MGMT_PERMS,
        List.of(TENANT_SYSTEM_ROLE_PERM)
    );

    /** Bundle assigned to {@code tenant-user-manager} on each tenant realm. */
    public static final List<String> TENANT_USER_MANAGER_BUNDLE = concat(
        TENANT_BASE_PERMS,
        TENANT_USER_MGMT_PERMS
    );

    /**
     * Every distinct atomic permission name (platform + tenant). Used by
     * {@code MeController} to filter JWT role claims down to just the
     * recognized atomic perms (excluding composite role names like
     * "tenant-admin" or "platform-admin").
     */
    public static final Set<String> ALL_KNOWN_PERMS = unmodifiableLinkedHashSet(
        concat(PLATFORM_PERMS, TENANT_ADMIN_BUNDLE)
    );

    /**
     * Every distinct tenant-level atomic permission (the union of all bundles
     * we install on tenant realms). Useful for the platform-admin cross-realm
     * flattening: a platform-admin should see every tenant-level perm too.
     */
    public static final List<String> ALL_TENANT_PERMS = TENANT_ADMIN_BUNDLE;

    @SafeVarargs
    private static List<String> concat(List<String>... lists) {
        List<String> out = new ArrayList<>();
        for (List<String> l : lists) out.addAll(l);
        return Collections.unmodifiableList(out);
    }

    private static Set<String> unmodifiableLinkedHashSet(List<String> items) {
        return Collections.unmodifiableSet(new LinkedHashSet<>(items));
    }
}
