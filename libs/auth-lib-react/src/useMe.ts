import { useQuery, type UseQueryResult } from '@tanstack/react-query';
import { useAuth } from 'react-oidc-context';
import type { MeResponse } from './types';

export interface UseMeOptions {
  /** Endpoint path. Defaults to '/api/me'. Admin-ui passes '/admin/api/v1/me'. */
  endpoint?: string;
  /** Cache TTL in ms. Default 60_000. */
  staleTime?: number;
  /**
   * Auth mode:
   * - `'pkce'` (default): use react-oidc-context's user.access_token as a Bearer.
   *   Query is disabled until the user has a token. REQUIRES an enclosing
   *   `<AuthProvider>` from react-oidc-context.
   * - `'cookie'`: send `credentials: 'include'` (browser attaches bff_sid).
   *   No Bearer header; does NOT call into react-oidc-context. Always enabled.
   *
   * If unset, defaults to `'pkce'` for backward compat. A given app must
   * choose one mode and keep it stable across renders.
   */
  authMode?: 'pkce' | 'cookie';
}

export function useMe(opts: UseMeOptions = {}): UseQueryResult<MeResponse, Error> {
  const endpoint = opts.endpoint ?? '/api/me';
  const staleTime = opts.staleTime ?? 60_000;
  const authMode = opts.authMode ?? 'pkce';

  // NOTE: branching on a stable prop is fine for rules-of-hooks because the
  // same branch runs every render for a given app. Apps must NOT toggle
  // authMode dynamically.
  if (authMode === 'cookie') {
    // eslint-disable-next-line react-hooks/rules-of-hooks
    return useCookieMe(endpoint, staleTime);
  }
  // eslint-disable-next-line react-hooks/rules-of-hooks
  return usePkceMe(endpoint, staleTime);
}

function usePkceMe(endpoint: string, staleTime: number): UseQueryResult<MeResponse, Error> {
  const auth = useAuth();
  return useQuery<MeResponse, Error>({
    queryKey: ['me', endpoint, auth.user?.profile?.sub],
    enabled: auth.isAuthenticated && !!auth.user?.access_token,
    // staleTime: 0 + refetchOnMount: 'always' means each remount triggers a
    // fresh /me fetch (instead of serving potentially stale cached perms from
    // a prior session in the same browser tab). Combined with `usePermission`
    // default-DENY-while-loading, this eliminates the tab-flicker bug where
    // navigating across SPAs briefly renders forbidden tabs/buttons.
    staleTime: 0,
    gcTime: staleTime,
    refetchOnMount: 'always',
    refetchOnWindowFocus: true,
    queryFn: async () => {
      const res = await fetch(endpoint, {
        headers: { Authorization: `Bearer ${auth.user!.access_token}` },
      });
      if (!res.ok) {
        throw new Error(`GET ${endpoint} -> HTTP ${res.status}`);
      }
      return (await res.json()) as MeResponse;
    },
  });
}

function useCookieMe(endpoint: string, staleTime: number): UseQueryResult<MeResponse, Error> {
  return useQuery<MeResponse, Error>({
    queryKey: ['me', endpoint, 'cookie'],
    staleTime: 0,
    gcTime: staleTime,
    refetchOnMount: 'always',
    refetchOnWindowFocus: true,
    queryFn: async () => {
      const res = await fetch(endpoint, {
        credentials: 'include',
        headers: { Accept: 'application/json' },
      });
      if (!res.ok) {
        throw new Error(`GET ${endpoint} -> HTTP ${res.status}`);
      }
      return (await res.json()) as MeResponse;
    },
  });
}
