// Decode the access_token (NOT the id_token) to read role claims.
// KC by default puts resource_access + realm_access into the access_token
// but not the id_token, so react-oidc-context's auth.user.profile lacks them.
// Client-side decode is fine — the BACKEND validates the signature; the SPA
// just uses the claims to render the right UI.

export type AccessTokenClaims = {
  sub?: string;
  preferred_username?: string;
  email?: string;
  realm_access?: { roles?: string[] };
  resource_access?: Record<string, { roles?: string[] }>;
};

export function decodeAccessToken(token: string | undefined): AccessTokenClaims | null {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4);
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

export function hasClientRole(
  claims: AccessTokenClaims | null,
  client: string,
  role: string,
): boolean {
  return claims?.resource_access?.[client]?.roles?.includes(role) ?? false;
}

export function hasRealmRole(claims: AccessTokenClaims | null, role: string): boolean {
  return claims?.realm_access?.roles?.includes(role) ?? false;
}
