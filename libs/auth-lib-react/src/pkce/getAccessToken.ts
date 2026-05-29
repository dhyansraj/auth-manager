/**
 * Get the current access token without needing a React component context.
 * Useful for non-React modules (fetch wrappers, axios interceptors,
 * mesh-tool helpers).
 *
 * Returns null if no signed-in user is in sessionStorage.
 *
 * Reads the same sessionStorage key react-oidc-context writes
 * (`oidc.user:<iss>:<clientId>`), so the value is always in sync with
 * whatever react-oidc-context has loaded. PKCE-only — BFF doesn't expose
 * the token client-side.
 */
export function getAccessToken(): string | null {
  if (typeof sessionStorage === 'undefined') return null;
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    if (!key || !key.startsWith('oidc.user:')) continue;
    try {
      const raw = sessionStorage.getItem(key);
      if (!raw) continue;
      const parsed = JSON.parse(raw) as { access_token?: unknown };
      if (typeof parsed?.access_token === 'string') return parsed.access_token;
    } catch {
      // Ignore corrupt/non-JSON entries and keep scanning — there can be
      // multiple oidc.* keys if the user has touched more than one realm/client.
    }
  }
  return null;
}
