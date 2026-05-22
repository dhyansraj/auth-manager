import type { ReactNode } from 'react';
import { useMeContext } from './MeProvider';

export function usePermission(permission: string): boolean {
  const { me } = useMeContext();
  return me?.permissions?.includes(permission) ?? false;
}

export function useIsPlatformAdmin(): boolean {
  return useMeContext().me?.isPlatformAdmin ?? false;
}

export function useIsTenantAdmin(): boolean {
  return useMeContext().me?.isTenantAdmin ?? false;
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
