package io.mcpmesh.auth.manager.idp;

/**
 * Per-tenant view of one social-login identity provider.
 *
 * @param id          provider id ({@code "google"} or {@code "github"})
 * @param displayName human-readable label shown on the login button
 * @param enabled     true if an IdP instance exists on the tenant realm
 * @param available   true if platform OAuth creds are configured for this provider
 */
public record IdentityProviderDto(
    String id,
    String displayName,
    boolean enabled,
    boolean available
) {}
