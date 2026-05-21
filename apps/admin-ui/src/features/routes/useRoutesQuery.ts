import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { RoutingConfig } from '../../api/types';

export function routesQueryKey(slug: string) {
  return ['routes', slug] as const;
}

export function useRoutesQuery(slug: string) {
  return useQuery({
    queryKey: routesQueryKey(slug),
    queryFn: () => api.getRoutes(slug),
    enabled: !!slug,
  });
}

export function useReplaceRoutesMutation(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RoutingConfig) => api.replaceRoutes(slug, body),
    onSuccess: (data) => {
      qc.setQueryData(routesQueryKey(slug), data);
      qc.invalidateQueries({ queryKey: routesQueryKey(slug) });
    },
  });
}
