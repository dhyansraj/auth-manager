package io.mcpmesh.auth.manager.tenantmanifest;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.List;

/**
 * YAML/JSON-serializable export of a tenant's permission catalog and composite
 * roles. Phase 1: read-only export consumed by humans for review and (later)
 * by an apply endpoint. Field order in the YAML follows the record component
 * order: {@code meta}, {@code permissions}, {@code roles},
 * {@code identityProviders}, {@code defaultRoles}.
 *
 * <p>{@code identityProviders} and {@code defaultRoles} are nullable: a
 * manifest YAML/JSON that omits them parses fine, and apply() treats null as
 * "don't touch this section."
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TenantManifest(
    Meta meta,
    List<PermissionEntry> permissions,
    List<RoleEntry> roles,
    List<IdentityProviderEntry> identityProviders,
    List<String> defaultRoles
) {
    /** Back-compat constructor for callers/tests that predate the identityProviders + defaultRoles fields. */
    public TenantManifest(Meta meta,
                          List<PermissionEntry> permissions,
                          List<RoleEntry> roles) {
        this(meta, permissions, roles, null, null);
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Meta(
        String tenantSlug,
        String realmName,
        Instant generatedAt,
        String version
    ) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PermissionEntry(
        String id,
        String description,
        String client
    ) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record RoleEntry(
        String name,
        String description,
        List<String> permissions
    ) {}

    /**
     * One brokered IdP entry. {@code id} is the KC alias (e.g. {@code google},
     * {@code github}). {@code enabled} is null-tolerant: null is treated as
     * true on apply.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record IdentityProviderEntry(
        String id,
        Boolean enabled
    ) {}
}
