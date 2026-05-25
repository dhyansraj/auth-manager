import { createContext, useContext, type ReactNode } from 'react';
import { useMe, type UseMeOptions } from './useMe';
import type { MeResponse } from './types';

interface MeContextValue {
  me: MeResponse | undefined;
  /** True only on the very first fetch (no cached data yet). */
  isLoading: boolean;
  /**
   * True for any in-flight /me request — initial load, background refetch on
   * remount, refetch on window focus, manual refetch(). Permission gates
   * default-DENY while this is true so a stale cached `me` from a prior
   * session can't briefly leak forbidden affordances into the UI.
   */
  isFetching: boolean;
  error: Error | null;
  refetch: () => void;
}

const MeContext = createContext<MeContextValue | null>(null);

export function MeProvider({ children, ...opts }: { children: ReactNode } & UseMeOptions) {
  const q = useMe(opts);
  const value: MeContextValue = {
    me: q.data,
    isLoading: q.isLoading,
    isFetching: q.isFetching,
    error: q.error,
    refetch: () => {
      void q.refetch();
    },
  };
  return <MeContext.Provider value={value}>{children}</MeContext.Provider>;
}

export function useMeContext(): MeContextValue {
  const ctx = useContext(MeContext);
  if (!ctx) throw new Error('useMeContext must be used inside <MeProvider>');
  return ctx;
}
