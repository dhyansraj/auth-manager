export type { MeResponse } from './types';
export { decodeAccessToken, hasClientRole, hasRealmRole } from './claims';
export type { AccessTokenClaims } from './claims';
export { useMe } from './useMe';
export type { UseMeOptions } from './useMe';
export { MeProvider, useMeContext } from './MeProvider';
export {
  usePermission,
  useIsPlatformAdmin,
  useIsTenantAdmin,
  useCurrentTenant,
  useMeUser,
  RequirePermission,
  RequireRole,
} from './permissions';
export { createOidcConfig } from './oidcConfig';
export type { CreateOidcConfigOptions, OidcConfig } from './oidcConfig';
export { AutoSignIn } from './AutoSignIn';
export type { AutoSignInProps } from './AutoSignIn';

// v0.3.0 PKCE SPA ergonomics (closes #97).
export { getAccessToken } from './pkce/getAccessToken';
export {
  SessionExpiryHandler,
  handleSessionExpired,
} from './pkce/SessionExpiryHandler';

// BFF (cookie-based auth) — see docs/bff.md for the migration guide.
// These exports are additive; the PKCE exports above are unchanged.
//
// v0.3.0: PlatformAuthProvider unifies BffAuthProvider + MeProvider into one
// component so SPAs don't have to stack them manually (#95). The old
// BffAuthProvider / useBffAuth exports remain for back-compat (deprecated).
export { PlatformAuthProvider } from './bff/PlatformAuthProvider';
export type {
  PlatformAuthContextValue,
  PlatformAuthProviderProps,
  PlatformAuthUser,
} from './bff/PlatformAuthProvider';
export {
  usePlatformAuth,
  usePermission as useBffPermission,
  RequirePermission as RequireBffPermission,
} from './bff/usePlatformAuth';
export { BffAuthProvider } from './bff/BffAuthProvider';
export type { BffAuthContextValue, BffAuthProviderProps, BffUser } from './bff/BffAuthProvider';
export { useBffAuth } from './bff/useBffAuth';
export { BffAutoSignIn } from './bff/BffAutoSignIn';
export type { BffAutoSignInProps } from './bff/BffAutoSignIn';
export {
  bffFetch,
  signinRedirect as bffSigninRedirect,
  signoutRedirect as bffSignoutRedirect,
} from './bff/bffClient';
