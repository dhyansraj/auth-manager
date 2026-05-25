import { useEffect } from 'react';
import { useBffAuth } from './useBffAuth';
import { signinRedirect } from './bffClient';

export interface BffAutoSignInProps {
  /** Override the splash text. Default: "Signing in…" */
  splashText?: string;
  /** Override the heading shown alongside the splash. */
  heading?: string;
  /** Extra subtitle below the heading (e.g., "Sign in to manage your tenant."). */
  subtitle?: string;
  /** If true, render a manual Sign In button instead of auto-redirecting. */
  manual?: boolean;
}

/**
 * Cookie-flow equivalent of <AutoSignIn />: when the user is not authenticated,
 * redirect them to `/_bff/login?redirect_back=<here>` so the edge can start the
 * OIDC flow on their behalf.
 *
 * Place this anywhere underneath <BffAuthProvider>. Typically you render it
 * at the root, gated on `!isAuthenticated`, e.g.:
 *
 *   const { isAuthenticated, isLoading } = useBffAuth();
 *   if (isLoading) return <Splash />;
 *   if (!isAuthenticated) return <BffAutoSignIn heading="My App" />;
 *   return <Routes>...</Routes>;
 */
export function BffAutoSignIn({
  splashText = 'Signing in…',
  heading,
  subtitle,
  manual = false,
}: BffAutoSignInProps) {
  const { isAuthenticated, isLoading, error } = useBffAuth();

  useEffect(() => {
    if (manual) return;
    if (isAuthenticated || isLoading) return;
    // If the /me probe is failing (network down, edge 5xx, etc.) don't loop
    // through /_bff/login — show the error instead and let the user retry.
    if (error) return;
    signinRedirect();
  }, [manual, isAuthenticated, isLoading, error]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50">
      <div className="text-center space-y-6 max-w-md px-6">
        {heading && (
          <div className="space-y-2">
            <h1 className="text-4xl font-bold text-slate-900 tracking-tight">{heading}</h1>
            {subtitle && <p className="text-slate-600 text-lg">{subtitle}</p>}
          </div>
        )}
        {error ? (
          <div className="space-y-3 text-left bg-red-50 border border-red-200 rounded p-4">
            <div className="text-red-800 font-semibold text-sm">Sign-in failed</div>
            <div className="text-red-700 text-sm break-words">{error.message}</div>
            <button
              onClick={() => window.location.reload()}
              className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded text-sm font-medium"
            >
              Retry
            </button>
          </div>
        ) : manual ? (
          <button
            onClick={() => signinRedirect()}
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
