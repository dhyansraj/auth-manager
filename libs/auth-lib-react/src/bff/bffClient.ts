/**
 * BFF client primitives — shared fetch wrapper, CSRF cookie reader, and
 * the module-level signinRedirect/signoutRedirect helpers.
 *
 * These do NOT depend on React and can be used outside the provider tree
 * (e.g. from imperative event handlers, route loaders, or vanilla JS).
 */

const CSRF_COOKIE_NAME = 'bff_csrf';

/**
 * Read the bff_csrf cookie from document.cookie.
 * Private — exported only for tests. SPAs should use bffFetch() which
 * attaches the header automatically.
 */
export function readCsrfCookie(): string | null {
  if (typeof document === 'undefined') return null;
  const cookies = document.cookie ? document.cookie.split('; ') : [];
  for (const c of cookies) {
    const eq = c.indexOf('=');
    if (eq === -1) continue;
    const name = c.slice(0, eq);
    if (name === CSRF_COOKIE_NAME) {
      return decodeURIComponent(c.slice(eq + 1));
    }
  }
  return null;
}

/**
 * Redirect the browser to /_bff/login, preserving where the user was so the
 * edge can send them back after the OIDC dance.
 *
 * @param targetPath  optional path+search to return to; defaults to current location
 */
export function signinRedirect(targetPath?: string): void {
  const target = targetPath ?? (window.location.pathname + window.location.search);
  window.location.assign(`/_bff/login?redirect_back=${encodeURIComponent(target)}`);
}

/**
 * Sign the user out: POST /_bff/logout (with CSRF), then send them to /.
 *
 * The edge clears the bff_sid + bff_csrf cookies and deletes the Redis
 * session. Returns once the navigation has been kicked off; in practice
 * the page unload happens before the promise's continuation runs.
 */
export async function signoutRedirect(): Promise<void> {
  try {
    await fetch('/_bff/logout', {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRF-Token': readCsrfCookie() ?? '' },
    });
  } catch {
    // Network errors shouldn't block the redirect — the user clicked sign-out,
    // we should still get them off the page.
  }
  window.location.assign('/');
}

/**
 * Fetch wrapper for BFF-mode SPAs. Always sends cookies, and attaches the
 * X-CSRF-Token header on state-changing requests (POST/PUT/PATCH/DELETE)
 * by reading the bff_csrf cookie.
 *
 * Use this for ALL API calls from a BFF SPA. Raw fetch() will work for GETs
 * but will be rejected by the edge for writes (csrf_mismatch).
 */
export async function bffFetch(url: string, opts: RequestInit = {}): Promise<Response> {
  const method = (opts.method ?? 'GET').toUpperCase();
  const headers = new Headers(opts.headers ?? {});
  if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
    if (!headers.has('X-CSRF-Token')) {
      const csrf = readCsrfCookie();
      if (csrf) headers.set('X-CSRF-Token', csrf);
    }
  }
  return fetch(url, {
    ...opts,
    credentials: 'include',
    headers,
  });
}
