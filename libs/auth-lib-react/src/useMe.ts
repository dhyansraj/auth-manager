import { useQuery, type UseQueryResult } from '@tanstack/react-query';
import { useAuth } from 'react-oidc-context';
import type { MeResponse } from './types';

export interface UseMeOptions {
  /** Endpoint path. Defaults to '/api/me'. Admin-ui passes '/admin/api/v1/me'. */
  endpoint?: string;
  /** Cache TTL in ms. Default 60_000. */
  staleTime?: number;
}

export function useMe(opts: UseMeOptions = {}): UseQueryResult<MeResponse, Error> {
  const auth = useAuth();
  const endpoint = opts.endpoint ?? '/api/me';
  const staleTime = opts.staleTime ?? 60_000;

  return useQuery<MeResponse, Error>({
    queryKey: ['me', endpoint, auth.user?.profile?.sub],
    enabled: auth.isAuthenticated && !!auth.user?.access_token,
    staleTime,
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
