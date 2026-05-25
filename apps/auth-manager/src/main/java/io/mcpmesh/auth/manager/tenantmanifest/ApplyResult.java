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
 * incoming manifest omits those sections. Phase 2 never deletes: anything
 * present in KC but missing from the manifest surfaces in the
 * {@code skippedAsMissing} bucket and a warning.
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
        List<String> skippedAsMissing
    ) {
        public static Diff empty() {
            return new Diff(List.of(), List.of(), List.of(), List.of());
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
