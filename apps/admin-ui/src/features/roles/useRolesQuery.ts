import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { CreateRoleRequest, UpdateRoleRequest } from '../../api/types';

export const permissionsQueryKey = (slug: string) => ['permissions', slug] as const;
export const rolesQueryKey = (slug: string) => ['roles', slug] as const;

export function usePermissionsQuery(slug: string) {
  return useQuery({
    queryKey: permissionsQueryKey(slug),
    queryFn: () => api.listPermissions(slug),
    enabled: !!slug,
  });
}

export function useRolesQuery(slug: string) {
  return useQuery({
    queryKey: rolesQueryKey(slug),
    queryFn: () => api.listRoles(slug),
    enabled: !!slug,
  });
}

export function useCreateRoleMutation(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateRoleRequest) => api.createRole(slug, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: rolesQueryKey(slug) }),
  });
}

export function useUpdateRoleMutation(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ name, body }: { name: string; body: UpdateRoleRequest }) =>
      api.updateRole(slug, name, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: rolesQueryKey(slug) }),
  });
}

export function useDeleteRoleMutation(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api.deleteRole(slug, name),
    onSuccess: () => qc.invalidateQueries({ queryKey: rolesQueryKey(slug) }),
  });
}
