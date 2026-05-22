import { useEffect } from 'react';
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

export function AutoSignIn({ splashText = 'Signing in…', heading, subtitle, manual = false }: AutoSignInProps) {
  const auth = useAuth();
  const isAuthOrBusy = auth.isAuthenticated || auth.activeNavigator || auth.isLoading;

  useEffect(() => {
    if (manual) return;
    if (isAuthOrBusy) return;
    // Defensive: don't re-initiate if URL already has a code/state (callback handling).
    const params = new URLSearchParams(window.location.search);
    if (params.has('code') || params.has('state') || params.has('error')) return;
    auth.signinRedirect().catch(() => {
      // If silent flow fails for some reason, leave the splash up. User can refresh.
    });
  }, [manual, isAuthOrBusy, auth]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50">
      <div className="text-center space-y-6 max-w-md px-6">
        {heading && (
          <div className="space-y-2">
            <h1 className="text-4xl font-bold text-slate-900 tracking-tight">{heading}</h1>
            {subtitle && <p className="text-slate-600 text-lg">{subtitle}</p>}
          </div>
        )}
        {manual ? (
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
