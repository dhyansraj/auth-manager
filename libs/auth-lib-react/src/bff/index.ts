// Barrel for BFF (cookie-based) exports. Kept separate from PKCE code so the
// two auth flows can evolve independently. Public consumers normally import
// from the package root; this barrel is for internal organization.
export { BffAuthProvider, BffAuthContext } from './BffAuthProvider';
export type { BffAuthContextValue, BffAuthProviderProps, BffUser } from './BffAuthProvider';
export { useBffAuth } from './useBffAuth';
export { BffAutoSignIn } from './BffAutoSignIn';
export type { BffAutoSignInProps } from './BffAutoSignIn';
export { bffFetch, signinRedirect, signoutRedirect, readCsrfCookie } from './bffClient';
