package io.mcpmesh.auth.manager.routing.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * A single path-prefix routing rule consumed by OpenResty's route.lua.
 *
 * <p>{@code path} uses glob-style patterns ({@code /api/*}, {@code /*}, etc.).
 * {@code target} is a logical key into {@link RoutingConfig#targets()}
 * (e.g. {@code "backend"}, {@code "frontend"}).
 *
 * <p>{@code bypassCsrf} (optional, default {@code false}) skips the
 * double-submit CSRF check on cookie-authed mutations for this rule. Use
 * sparingly: only for embedded third-party UIs (e.g. Redis Commander,
 * Grafana) that have their own session model and don't know about the
 * platform's {@code bff_csrf} cookie / {@code X-CSRF-Token} header. The
 * route must still be gated by realm-level access (REQUIRED auth) and
 * should lead to a self-contained tool that does not transact with the
 * SPA's API surface.
 *
 * <p>{@code requiredPermission} (optional, may be {@code null} or empty) is
 * the id of a single permission claim that must be present in the caller's
 * JWT (in {@code resource_access.<client>.roles[]} or
 * {@code realm_access.roles[]}) for the request to proceed. Only enforced
 * when {@code authMode == REQUIRED}; ignored otherwise. Use to gate ops
 * tools (Redis Commander, Grafana, ...) by role on multi-user tenants
 * where some users are operators and others are not. Verbatim string
 * match -- the router does not look up a permission catalog. Operators
 * are responsible for typing an id their apps emit.
 *
 * <p>{@code stripPrefix} (optional, may be {@code null} or empty) tells the
 * router to drop this prefix from the request URI before forwarding to the
 * upstream. Use for embedded third-party apps mounted under a subpath whose
 * internal links assume root (e.g. Redis Commander at {@code /ops/redis/*}
 * whose internal API calls go to {@code /apiv2/...} without the prefix). The
 * value should normally be the rule's {@code path} minus the trailing
 * {@code /*}. If the configured prefix is not actually a prefix of the
 * matched request path, the router proxies as-is (no-op).
 *
 * <p>{@code maxBodyMb} (optional, may be {@code null}) is the per-route
 * request-body cap in megabytes. When set, the router reads
 * {@code Content-Length} on body-carrying methods (POST/PUT/PATCH/DELETE) and
 * returns {@code 413 Payload Too Large} BEFORE forwarding upstream if the
 * declared length exceeds {@code maxBodyMb * 1024 * 1024} bytes. When unset
 * (null), routes fall back to a platform-wide default (see
 * {@code ROUTE_DEFAULT_MAX_BODY_MB}, default 25 MB). The absolute upper bound
 * is enforced by nginx's {@code client_max_body_size 100m} (the Cloudflare
 * Free tunnel ceiling) regardless of this value. Requests without a
 * Content-Length header (e.g. chunked uploads) are NOT rejected here — the
 * nginx ceiling is the only check.
 *
 * <p>JSON deserialization tolerates missing {@code bypassCsrf} /
 * {@code requiredPermission} / {@code stripPrefix} / {@code maxBodyMb}
 * fields (Jackson defaults boolean to {@code false} and the other types to
 * {@code null}), so older wire payloads remain compatible.
 */
public record RoutingRule(
    @NotBlank String path,
    @NotNull AuthMode authMode,
    @NotBlank String target,
    boolean bypassCsrf,
    String requiredPermission,
    String stripPrefix,
    Integer maxBodyMb
) {
    /** Back-compat convenience constructor: bypassCsrf + requiredPermission + stripPrefix + maxBodyMb default. */
    public RoutingRule(String path, AuthMode authMode, String target) {
        this(path, authMode, target, false, null, null, null);
    }

    /** Back-compat convenience constructor: requiredPermission + stripPrefix + maxBodyMb default to null. */
    public RoutingRule(String path, AuthMode authMode, String target, boolean bypassCsrf) {
        this(path, authMode, target, bypassCsrf, null, null, null);
    }

    /** Back-compat convenience constructor: stripPrefix + maxBodyMb default to null. */
    public RoutingRule(String path, AuthMode authMode, String target, boolean bypassCsrf, String requiredPermission) {
        this(path, authMode, target, bypassCsrf, requiredPermission, null, null);
    }

    /** Back-compat convenience constructor: maxBodyMb defaults to null. */
    public RoutingRule(String path, AuthMode authMode, String target, boolean bypassCsrf, String requiredPermission, String stripPrefix) {
        this(path, authMode, target, bypassCsrf, requiredPermission, stripPrefix, null);
    }
}
