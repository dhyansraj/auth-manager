package io.mcpmesh.auth.manager.tenantmanifest;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

/**
 * Response from {@code POST /api/v1/tenants/{slug}/manifest:apply}. Captures
 * the plan (or executed mutations) for permissions and (optionally) composite
 * roles, plus the result of the role-hash tripwire check.
 *
 * <p>{@code roles} and {@code hashTripwire} are null when {@code applyRoles=false}.
 * {@code identityProviders} and {@code defaultRoleMappers} are null when the
 * incoming manifest omits those sections.
 *
 * <p>{@code Diff.skipped} = items present in KC but absent from the manifest
 * that were left untouched (additive sections: permissions, roles, IdPs).
 * {@code Diff.deleted} = items present in KC but absent from the manifest
 * that were actively removed because the manifest section is authoritative
 * (currently: defaultRoleMappers).
 *
 * <p>For {@code defaultRoleMappers}, diff entries are formatted as
 * {@code <idpAlias>:<roleName>} (e.g. {@code google:customer}).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApplyResult(
    boolean dryRun,
    Diff permissions,
    Diff roles,
    Diff identityProviders,
    Diff defaultRoleMappers,
    HashTripwireResult hashTripwire,
    List<String> warnings
) {
    /** Back-compat constructor for callers/tests that predate identityProviders + defaultRoleMappers. */
    public ApplyResult(boolean dryRun,
                       Diff permissions,
                       Diff roles,
                       HashTripwireResult hashTripwire,
                       List<String> warnings) {
        this(dryRun, permissions, roles, null, null, hashTripwire, warnings);
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Diff(
        List<String> created,
        List<String> updated,
        List<String> unchanged,
        List<String> skipped,
        List<String> deleted
    ) {
        public static Diff empty() {
            return new Diff(List.of(), List.of(), List.of(), List.of(), List.of());
        }

        /** Back-compat constructor for sections that don't delete (permissions, roles, IdPs). */
        public Diff(List<String> created, List<String> updated,
                    List<String> unchanged, List<String> skipped) {
            this(created, updated, unchanged, skipped, List.of());
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record HashTripwireResult(
        String storedHash,
        String currentHash,
        boolean match,
        boolean tripped,
        String newHashAfterApply
    ) {}
}
