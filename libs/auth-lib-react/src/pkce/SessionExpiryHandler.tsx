import { useEffect, type ReactNode } from 'react';
import { useAuth } from 'react-oidc-context';

/**
 * Imperative "session ended — get the user out of here cleanly" routine.
 *
 * Clears every `oidc.*` key from sessionStorage (so a stale, expired user
 * stub can't be re-loaded by react-oidc-context on remount) and reloads to
 * `/` with `window.location.assign('/')` — a full reload drops in-memory
 * React state and triggers the AutoSignIn dance from a clean slate.
 *
 * Exported so non-React paths (axios interceptors, mesh-tool helpers) can
 * call it on a 401 response without having to dispatch into the React tree.
 */
export function handleSessionExpired(): void {
  if (typeof sessionStorage !== 'undefined') {
    for (let i = sessionStorage.length - 1; i >= 0; i--) {
      const k = sessionStorage.key(i);
      if (k && k.startsWith('oidc')) sessionStorage.removeItem(k);
    }
  }
  if (typeof window !== 'undefined') {
    window.location.assign('/');
  }
}

/**
 * Children-passthrough component that wires up
 * `auth.events.addUserSignedOut` + `addAccessTokenExpired` from
 * react-oidc-context. On either event it calls `handleSessionExpired()` so
 * the SPA bounces back to `/` with a clean sessionStorage.
 *
 * Mount once near the root, INSIDE the `<AuthProvider>` from
 * react-oidc-context. PKCE-only.
 */
export function SessionExpiryHandler({ children }: { children: ReactNode }) {
  const auth = useAuth();

  useEffect(() => {
    if (!auth?.events) return;
    const unsubSignedOut = auth.events.addUserSignedOut(() => {
      handleSessionExpired();
    });
    const unsubExpired = auth.events.addAccessTokenExpired(() => {
      handleSessionExpired();
    });
    return () => {
      unsubSignedOut?.();
      unsubExpired?.();
    };
  }, [auth]);

  return <>{children}</>;
}
