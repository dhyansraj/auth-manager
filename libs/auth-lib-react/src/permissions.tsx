import type { ReactNode } from 'react';
import { useMeContext } from './MeProvider';

/**
 * Returns true iff /me has resolved AND the caller holds the named permission.
 *
 * IMPORTANT: while /me is in-flight (initial load OR background refetch on
 * remount/focus) or `me` is undefined, this MUST return `false`. Otherwise
 * gated UI (tabs, buttons, links) momentarily renders the full set during the
 * transition and then collapses to the actual subset once /me lands — which
 * reads as a "flicker" of forbidden affordances. Default-DENY here makes the
 * bug impossible at the source, even if a stale cached /me from a prior
 * privileged session is sitting in the React Query cache.
 */
export function usePermission(permission: string): boolean {
  const { me, isLoading, isFetching } = useMeContext();
  if (isLoading || isFetching || !me) return false;
  return me.permissions?.includes(permission) ?? false;
}

/**
 * @deprecated Role-based check. Prefer `usePermission(<perm>)` against an
 * atomic permission from the tenant manifest (e.g. `'TENANT_LIST_ALL'`).
 * Kept for back-compat with older consumers; safe to use but new code
 * should gate on permissions, not role names.
 */
export function useIsPlatformAdmin(): boolean {
  const { me, isLoading, isFetching } = useMeContext();
  if (isLoading || isFetching || !me) return false;
  return me.isPlatformAdmin ?? false;
}

/**
 * @deprecated Role-based check. Prefer `usePermission(<perm>)` against the
 * atomic permission the gate actually controls (e.g. `'ROUTES_EDIT'`,
 * `'USER_LIST'`). Kept for back-compat.
 */
export function useIsTenantAdmin(): boolean {
  const { me, isLoading, isFetching } = useMeContext();
  if (isLoading || isFetching || !me) return false;
  return me.isTenantAdmin ?? false;
}

export function useCurrentTenant() {
  return useMeContext().me?.tenant ?? null;
}

export function useMeUser() {
  return useMeContext().me?.user ?? null;
}

export function RequirePermission({
  permission,
  fallback = null,
  children,
}: {
  permission: string;
  fallback?: ReactNode;
  children: ReactNode;
}) {
  return usePermission(permission) ? <>{children}</> : <>{fallback}</>;
}

/**
 * @deprecated Role-based gate. Prefer `<RequirePermission perm="X">` against
 * an atomic permission from the tenant manifest. Kept for back-compat;
 * see app1's Home.tsx for the modern pattern.
 */
export function RequireRole({
  role,
  fallback = null,
  children,
}: {
  role: 'platform-admin' | 'tenant-admin';
  fallback?: ReactNode;
  children: ReactNode;
}) {
  const isPlatformAdmin = useIsPlatformAdmin();
  const isTenantAdmin = useIsTenantAdmin();
  const allow = role === 'platform-admin' ? isPlatformAdmin : isTenantAdmin;
  return allow ? <>{children}</> : <>{fallback}</>;
}
