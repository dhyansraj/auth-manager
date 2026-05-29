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
 * Merged user shape for the unified platform-auth provider.
 *
 * `profile` mirrors the minimal claims `BffAuthProvider` exposes (so the same
 * UI code can read `user.profile.sub` regardless of which provider is mounted).
 *
 * `me` is the TENANT BACKEND's /api/me payload when `platformContextOnly=false`
 * (the common SPA case), or the PLATFORM-EDGE's /_bff/me payload when
 * `platformContextOnly=true` (admin-ui case — no tenant backend). Both endpoints
 * return the same `MeResponse` shape so callers don't need to branch.
 */
export interface PlatformAuthUser {
  me: MeResponse;
  profile: {
    sub: string;
    email?: string;
    preferred_username?: string;
    name?: string;
  };
}

/**
 * Single context value covering BFF identity + tenant-backend permissions.
 *
 * `permissions` is the authoritative permission set the UI should gate on. It
 * is sourced from THE TENANT BACKEND'S /api/me (which knows the tenant's app
 * roles), NOT from /_bff/me (which only carries the 6 platform-usermanagement
 * client roles). This eliminates the "I stacked BffAuthProvider and read
 * useBffAuth().user?.me?.permissions and got an empty / platform-only set"
 * footgun that closes #95.
 */
export interface PlatformAuthContextValue {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: PlatformAuthUser | null;
  error: Error | null;
  /** Authoritative permission set — gate UI on this, not on `user.me.permissions`. */
  permissions: Set<string>;
  /** Re-fetch both /_bff/me and /api/me. */
  refresh: () => Promise<void>;
  signinRedirect: (targetPath?: string) => void;
  signoutRedirect: () => Promise<void>;
}

export const PlatformAuthContext = createContext<PlatformAuthContextValue | null>(null);

export interface PlatformAuthProviderProps {
  children: ReactNode;
  /** URL of the tenant backend's /me endpoint. Default: '/api/me'. */
  meEndpoint?: string;
  /**
   * If true, skip the /api/me fetch and source permissions from /_bff/me only.
   * Use this for platform-context apps (admin-ui) where there is no tenant
   * backend serving /api/me — permissions are the 6 platform roles. Default:
   * false (the common tenant-SPA case).
   */
  platformContextOnly?: boolean;
  /**
   * Endpoint that returns the BFF identity probe. Default: '/_bff/me'. Override
   * only if your edge mounts the BFF on a non-standard path.
   */
  bffMeEndpoint?: string;
}

/**
 * Unified BFF identity + tenant-backend permissions provider. Replaces the
 * two-provider stack of `<BffAuthProvider>` + `<MeProvider endpoint="/api/me">`
 * with a single component, and exposes one `usePlatformAuth()` hook whose
 * `permissions` Set is sourced from the right place by construction.
 *
 * See also: `usePlatformAuth`, `usePermission`, `RequirePermission` in
 * `./usePlatformAuth`.
 */
export function PlatformAuthProvider({
  children,
  meEndpoint = '/api/me',
  platformContextOnly = false,
  bffMeEndpoint = '/_bff/me',
}: PlatformAuthProviderProps) {
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<PlatformAuthUser | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [permissions, setPermissions] = useState<Set<string>>(() => new Set());
  // Prevent concurrent probes from clobbering each other on rapid remount.
  const inFlight = useRef<Promise<void> | null>(null);

  const probe = useCallback(async (): Promise<void> => {
    if (inFlight.current) return inFlight.current;
    const p = (async () => {
      try {
        // Step 1 — BFF identity probe. Determines whether we have a session.
        const bffRes = await fetch(bffMeEndpoint, {
          credentials: 'include',
          headers: { Accept: 'application/json' },
        });
        if (bffRes.status === 401) {
          setIsAuthenticated(false);
          setUser(null);
          setPermissions(new Set());
          setError(null);
          return;
        }
        if (!bffRes.ok) {
          throw new Error(`GET ${bffMeEndpoint} -> HTTP ${bffRes.status}`);
        }
        const bffMe = (await bffRes.json()) as MeResponse;

        // Step 2 — if platform-context-only, use the BFF payload as both
        // identity AND the source of permissions. Skip the /api/me fetch.
        if (platformContextOnly) {
          setUser({
            me: bffMe,
            profile: {
              sub: bffMe.user.id,
              email: bffMe.user.email,
              preferred_username: bffMe.user.preferredUsername,
              name: bffMe.user.name,
            },
          });
          setPermissions(new Set(bffMe.permissions ?? []));
          setIsAuthenticated(true);
          setError(null);
          return;
        }

        // Step 3 — fetch the tenant backend's /api/me for authoritative perms.
        const tenantRes = await fetch(meEndpoint, {
          credentials: 'include',
          headers: { Accept: 'application/json' },
        });
        if (tenantRes.status === 401) {
          // BFF said we have a session but the tenant backend disagrees.
          // Treat as anonymous so the SPA re-runs the login flow.
          setIsAuthenticated(false);
          setUser(null);
          setPermissions(new Set());
          setError(new Error(`GET ${meEndpoint} -> HTTP 401`));
          return;
        }
        if (tenantRes.status === 403) {
          // Authenticated but tenant backend won't grant any permissions.
          // Keep the user signed in with the BFF profile so the UI can render
          // a "no access" screen instead of bouncing back to login.
          setUser({
            me: bffMe,
            profile: {
              sub: bffMe.user.id,
              email: bffMe.user.email,
              preferred_username: bffMe.user.preferredUsername,
              name: bffMe.user.name,
            },
          });
          setPermissions(new Set());
          setIsAuthenticated(true);
          setError(null);
          return;
        }
        if (!tenantRes.ok) {
          throw new Error(`GET ${meEndpoint} -> HTTP ${tenantRes.status}`);
        }
        const tenantMe = (await tenantRes.json()) as MeResponse;
        setUser({
          me: tenantMe,
          profile: {
            sub: tenantMe.user.id ?? bffMe.user.id,
            email: tenantMe.user.email ?? bffMe.user.email,
            preferred_username:
              tenantMe.user.preferredUsername ?? bffMe.user.preferredUsername,
            name: tenantMe.user.name ?? bffMe.user.name,
          },
        });
        setPermissions(new Set(tenantMe.permissions ?? []));
        setIsAuthenticated(true);
        setError(null);
      } catch (e) {
        setError(e instanceof Error ? e : new Error(String(e)));
        setIsAuthenticated(false);
        setUser(null);
        setPermissions(new Set());
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
  }, [bffMeEndpoint, meEndpoint, platformContextOnly]);

  useEffect(() => {
    void probe();
  }, [probe]);

  const value = useMemo<PlatformAuthContextValue>(
    () => ({
      isAuthenticated,
      isLoading,
      user,
      error,
      permissions,
      refresh: probe,
      signinRedirect,
      signoutRedirect,
    }),
    [isAuthenticated, isLoading, user, error, permissions, probe],
  );

  return (
    <PlatformAuthContext.Provider value={value}>{children}</PlatformAuthContext.Provider>
  );
}
