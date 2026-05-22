import { createContext, useContext, type ReactNode } from 'react';
import { useMe, type UseMeOptions } from './useMe';
import type { MeResponse } from './types';

interface MeContextValue {
  me: MeResponse | undefined;
  isLoading: boolean;
  error: Error | null;
  refetch: () => void;
}

const MeContext = createContext<MeContextValue | null>(null);

export function MeProvider({ children, ...opts }: { children: ReactNode } & UseMeOptions) {
  const q = useMe(opts);
  const value: MeContextValue = {
    me: q.data,
    isLoading: q.isLoading,
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
