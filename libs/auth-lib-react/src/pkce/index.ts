// Barrel for PKCE (react-oidc-context based) exports. Mirrors the PKCE half of
// the root entry so new consumers can opt into PKCE-only imports and tree-shake
// the BFF code. The root entry remains kitchen-sink for back-compat.
export type { MeResponse } from '../types';
export { decodeAccessToken, hasClientRole, hasRealmRole } from '../claims';
export type { AccessTokenClaims } from '../claims';
export { useMe } from '../useMe';
export type { UseMeOptions } from '../useMe';
export { MeProvider, useMeContext } from '../MeProvider';
export {
  usePermission,
  useIsPlatformAdmin,
  useIsTenantAdmin,
  useCurrentTenant,
  useMeUser,
  RequirePermission,
  RequireRole,
} from '../permissions';
export { createOidcConfig } from '../oidcConfig';
export type { CreateOidcConfigOptions, OidcConfig } from '../oidcConfig';
export { AutoSignIn } from '../AutoSignIn';
export type { AutoSignInProps } from '../AutoSignIn';
