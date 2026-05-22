import { useQueries } from '@tanstack/react-query';
import { api } from '../../api/client';

/**
 * Per-row fetch of `realmRoles` for users in the tenant. The list endpoint
 * only returns system client-roles, so we N+1 the slug-keyed user endpoint
 * to surface composite role assignments in the table. Cached + parallel via
 * TanStack `useQueries`.
 */
export function useUserRealmRolesQueries(slug: string, userIds: string[]) {
  const results = useQueries({
    queries: userIds.map(userId => ({
      queryKey: ['user-detail', slug, userId] as const,
      queryFn: () => api.getUserBySlug(slug, userId),
      staleTime: 30_000,
    })),
  });

  const map: Record<string, string[]> = {};
  results.forEach((r, i) => {
    const id = userIds[i];
    if (r.data?.realmRoles) map[id] = r.data.realmRoles;
  });
  return map;
}
