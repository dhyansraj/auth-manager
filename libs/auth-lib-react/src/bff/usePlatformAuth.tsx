import { useContext, type ReactNode } from 'react';
import {
  PlatformAuthContext,
  type PlatformAuthContextValue,
} from './PlatformAuthProvider';

/**
 * Access the unified platform-auth context. Throws if called outside
 * `<PlatformAuthProvider>`.
 */
export function usePlatformAuth(): PlatformAuthContextValue {
  const ctx = useContext(PlatformAuthContext);
  if (!ctx) {
    throw new Error(
      'usePlatformAuth() must be called inside <PlatformAuthProvider>. ' +
        'If you are still on the legacy <BffAuthProvider> + <MeProvider> stack, ' +
        'use useBffAuth() / useMeContext() instead.',
    );
  }
  return ctx;
}

/**
 * Return true iff the provider has resolved AND the user holds `permission`.
 *
 * Default-DENY while loading: matches the tab-flicker fix documented for
 * `usePermission()` against MeProvider — gated UI must not momentarily render
 * the full set during the transition and then collapse to the actual subset.
 */
export function usePermission(permission: string): boolean {
  const { permissions, isLoading } = usePlatformAuth();
  if (isLoading) return false;
  return permissions.has(permission);
}

export interface RequirePermissionProps {
  permission: string;
  fallback?: ReactNode;
  children: ReactNode;
}

/**
 * Render `children` iff the user holds `permission`, otherwise `fallback`.
 *
 * Thin wrapper around `usePermission` for the common gate-a-subtree pattern.
 * Must be used inside `<PlatformAuthProvider>`.
 */
export function RequirePermission({
  permission,
  fallback = null,
  children,
}: RequirePermissionProps) {
  return usePermission(permission) ? <>{children}</> : <>{fallback}</>;
}
