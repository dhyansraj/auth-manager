import {
  createContext,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import type { MeResponse } from '../types';
import { signinRedirect, signoutRedirect } from './bffClient';

/**
 * BFF "user" shape. Mirrors react-oidc-context's `User` minimally so existing
 * code reading `user.profile` keeps working. NOTE: there is NO `access_token`
 * here — the token lives in the server-side Redis session and is only
 * injected at the edge. SPAs cannot read it.
 */
export interface BffUser {
  /** The /me payload directly, exposed for convenience. */
  me: MeResponse;
  /** Mirrors `oidc-client-ts` User.profile loosely: subset of claims we know. */
  profile: {
    sub: string;
    email?: string;
    preferred_username?: string;
    name?: string;
  };
}

/**
 * Context value. Shape kept compatible with react-oidc-context's
 * `AuthContextProps` for the fields BFF can support, so SPAs migrating from
 * `useAuth()` to `useBffAuth()` mostly only need to change the import.
 *
 * Notable differences:
 * - `user.access_token` is INTENTIONALLY absent (BFF keeps the token server-side).
 * - `activeNavigator` is absent — the BFF login is a single full-page redirect,
 *   not a multi-state navigator state machine.
 * - `signinRedirect`/`signoutRedirect` here are simpler (no args mirror).
 */
export interface BffAuthContextValue {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: BffUser | null;
  error: Error | null;
  /** Re-fetch /me; useful after a permission/role change. */
  refresh: () => Promise<void>;
  signinRedirect: (targetPath?: string) => void;
  signoutRedirect: () => Promise<void>;
}

export const BffAuthContext = createContext<BffAuthContextValue | null>(null);

export interface BffAuthProviderProps {
  children: ReactNode;
  /**
   * Endpoint that returns the MeResponse for the cookie-authenticated user.
   * Defaults to `/_bff/me` (served by the edge; tunnels cookie -> Bearer to
   * the upstream `/api/v1/me`).
   *
   * Note: this is for the provider's auth probe only. MeProvider takes its own
   * endpoint prop and is responsible for the application-level /me fetch
   * (which may point to a different path, e.g. `/api/v1/me` directly).
   */
  meEndpoint?: string;
}

export function BffAuthProvider({ children, meEndpoint = '/_bff/me' }: BffAuthProviderProps) {
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<BffUser | null>(null);
  const [error, setError] = useState<Error | null>(null);
  // Prevent concurrent /me probes from clobbering each other on rapid remount.
  const inFlight = useRef<Promise<void> | null>(null);

  const probe = useCallback(async (): Promise<void> => {
    if (inFlight.current) return inFlight.current;
    const p = (async () => {
      try {
        const res = await fetch(meEndpoint, {
          credentials: 'include',
          headers: { Accept: 'application/json' },
        });
        if (res.status === 401) {
          setIsAuthenticated(false);
          setUser(null);
          setError(null);
          return;
        }
        if (!res.ok) {
          throw new Error(`GET ${meEndpoint} -> HTTP ${res.status}`);
        }
        const me = (await res.json()) as MeResponse;
        setUser({
          me,
          profile: {
            sub: me.user.id,
            email: me.user.email,
            preferred_username: me.user.preferredUsername,
            name: me.user.name,
          },
        });
        setIsAuthenticated(true);
        setError(null);
      } catch (e) {
        setError(e instanceof Error ? e : new Error(String(e)));
        setIsAuthenticated(false);
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    })();
    inFlight.current = p;
    try {
      await p;
    } finally {
      inFlight.current = null;
    }
  }, [meEndpoint]);

  useEffect(() => {
    void probe();
  }, [probe]);

  const value = useMemo<BffAuthContextValue>(
    () => ({
      isAuthenticated,
      isLoading,
      user,
      error,
      refresh: probe,
      signinRedirect,
      signoutRedirect,
    }),
    [isAuthenticated, isLoading, user, error, probe],
  );

  return <BffAuthContext.Provider value={value}>{children}</BffAuthContext.Provider>;
}
