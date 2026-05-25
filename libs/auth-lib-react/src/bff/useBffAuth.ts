import { useContext } from 'react';
import { BffAuthContext, type BffAuthContextValue } from './BffAuthProvider';

/**
 * Access the BFF auth context. Throws if called outside `<BffAuthProvider>`.
 *
 * Drop-in-ish replacement for `useAuth()` from react-oidc-context. See
 * `BffAuthContextValue` for the differences vs `AuthContextProps`.
 */
export function useBffAuth(): BffAuthContextValue {
  const ctx = useContext(BffAuthContext);
  if (!ctx) {
    throw new Error(
      'useBffAuth() must be called inside <BffAuthProvider>. ' +
        'If you are using the PKCE flow, use useAuth() from react-oidc-context instead.',
    );
  }
  return ctx;
}
