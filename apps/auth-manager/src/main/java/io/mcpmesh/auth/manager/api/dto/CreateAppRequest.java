package io.mcpmesh.auth.manager.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

public record CreateAppRequest(

    @NotBlank
    @Size(min = 3, max = 63)
    @Pattern(regexp = "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$",
             message = "must be lowercase alphanumeric, hyphens allowed, no leading/trailing hyphen")
    String slug,

    @NotBlank
    @Size(min = 1, max = 100)
    String displayName,

    /** Default: CONFIDENTIAL_BACKEND for back-compat with existing callers. */
    AppProfile profile,

    /** Other client slugs this app's tokens should carry as audience (oidc-audience-mapper).
     *  Applied AFTER client creation. Empty/null = no mappers. */
    List<String> audience
) {
    public enum AppProfile {
        /** Default. Confidential client with serviceAccountsEnabled=true. Suitable
         *  for any backend that needs to mint tokens via client_credentials OR
         *  participate in standard auth-code flow with a secret. */
        CONFIDENTIAL_BACKEND,
        /** Public PKCE-S256 client for SPAs. Redirect URIs derived from the tenant's
         *  registered hostnames; web origins derived likewise. Lightweight tokens
         *  disabled. No service account, no direct grants. */
        SPA_PKCE,
        /** Confidential client for machine-to-machine ONLY. Service accounts on,
         *  standardFlow off, directGrants off. Suitable for backend daemons /
         *  cron jobs that mint via client_credentials. */
        SERVICE_ACCOUNT_ONLY
    }
}
