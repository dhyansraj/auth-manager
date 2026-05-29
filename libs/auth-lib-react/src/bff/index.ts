// Barrel for BFF (cookie-based) exports. Kept separate from PKCE code so the
// two auth flows can evolve independently. Public consumers normally import
// from the package root; this barrel is for internal organization.

// --- v0.3.0 unified provider (closes #95) -----------------------------------
// PlatformAuthProvider replaces the two-provider stack of <BffAuthProvider> +
// <MeProvider endpoint="/api/me"> with a single component whose `permissions`
// Set is sourced from the tenant backend's /api/me (NOT /_bff/me, which only
// carries platform-usermanagement client roles). New code should use this.
export { PlatformAuthProvider, PlatformAuthContext } from './PlatformAuthProvider';
export type {
  PlatformAuthContextValue,
  PlatformAuthProviderProps,
  PlatformAuthUser,
} from './PlatformAuthProvider';
export { usePlatformAuth, usePermission, RequirePermission } from './usePlatformAuth';
export type { RequirePermissionProps } from './usePlatformAuth';

// --- Legacy primitives (kept for back-compat; admin-ui depends on them) -----
/**
 * @deprecated Use `PlatformAuthProvider` instead. `BffAuthProvider` only
 * exposes the /_bff/me payload, whose `permissions` array contains the 6
 * platform-usermanagement client roles — NOT the tenant's app-level
 * permissions. Stacking `<BffAuthProvider>` + `<MeProvider endpoint="/api/me">`
 * is the historical workaround; `PlatformAuthProvider` bundles both and exposes
 * a single `usePlatformAuth()` hook whose `permissions` Set is sourced from
 * /api/me by default. See PlatformAuthProvider.tsx for the migration story.
 */
export { BffAuthProvider, BffAuthContext } from './BffAuthProvider';
export type { BffAuthContextValue, BffAuthProviderProps, BffUser } from './BffAuthProvider';
/** @deprecated Use `usePlatformAuth` instead. See `BffAuthProvider` deprecation note. */
export { useBffAuth } from './useBffAuth';
export { BffAutoSignIn } from './BffAutoSignIn';
export type { BffAutoSignInProps } from './BffAutoSignIn';
export { bffFetch, signinRedirect, signoutRedirect, readCsrfCookie } from './bffClient';
