import { useEffect, useState } from 'react';
import { useAuth } from 'react-oidc-context';

export interface AutoSignInProps {
  /** Override the splash text. Default: "Signing in…" */
  splashText?: string;
  /** Override the heading shown alongside the splash. */
  heading?: string;
  /** If true, render a manual Sign In button instead of auto-redirecting. */
  manual?: boolean;
  /** Extra subtitle below the heading (e.g., "Sign in to manage your tenant.") */
  subtitle?: string;
}

/**
 * Wipe every sessionStorage key starting with "oidc" — these are the
 * react-oidc-context PKCE/state entries. Used by the "Clear session and
 * retry" button to recover from stale-state / invalid-code / network-error
 * callback failures without the user having to manually clear storage.
 */
function clearOidcSessionAndReload() {
  for (let i = sessionStorage.length - 1; i >= 0; i--) {
    const k = sessionStorage.key(i);
    if (k && k.startsWith('oidc')) sessionStorage.removeItem(k);
  }
  window.location.reload();
}

export function AutoSignIn({ splashText = 'Signing in…', heading, subtitle, manual = false }: AutoSignInProps) {
  const auth = useAuth();
  const isAuthOrBusy = auth.isAuthenticated || auth.activeNavigator || auth.isLoading;
  // Surfaced when signinRedirect() itself throws (separate from auth.error
  // which covers callback-handling failures inside react-oidc-context).
  const [redirectError, setRedirectError] = useState<Error | null>(null);

  useEffect(() => {
    if (manual) return;
    if (isAuthOrBusy) return;
    if (auth.error || redirectError) return;
    // Defensive: don't re-initiate if URL already has a code/state (callback handling).
    const params = new URLSearchParams(window.location.search);
    if (params.has('code') || params.has('state') || params.has('error')) return;
    auth.signinRedirect().catch((e) => {
      setRedirectError(e instanceof Error ? e : new Error(String(e)));
    });
  }, [manual, isAuthOrBusy, auth, redirectError]);

  const displayedError = auth.error ?? redirectError;

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50">
      <div className="text-center space-y-6 max-w-md px-6">
        {heading && (
          <div className="space-y-2">
            <h1 className="text-4xl font-bold text-slate-900 tracking-tight">{heading}</h1>
            {subtitle && <p className="text-slate-600 text-lg">{subtitle}</p>}
          </div>
        )}
        {displayedError ? (
          <div className="space-y-3 text-left bg-red-50 border border-red-200 rounded p-4">
            <div className="text-red-800 font-semibold text-sm">Sign-in failed</div>
            <div className="text-red-700 text-sm break-words">{displayedError.message}</div>
            <button
              onClick={clearOidcSessionAndReload}
              className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded text-sm font-medium"
            >
              Clear session and retry
            </button>
          </div>
        ) : manual ? (
          <button
            onClick={() => auth.signinRedirect()}
            className="bg-slate-900 hover:bg-slate-800 text-white px-10 py-4 rounded-lg shadow text-lg font-medium"
          >
            Sign in
          </button>
        ) : (
          <div className="text-slate-500 text-sm flex items-center justify-center gap-2">
            <span className="inline-block w-4 h-4 border-2 border-slate-300 border-t-slate-700 rounded-full animate-spin" />
            {splashText}
          </div>
        )}
      </div>
    </div>
  );
}
