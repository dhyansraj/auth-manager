import { useAuth } from 'react-oidc-context';
import { Link } from 'react-router-dom';
import { RequireRole, useMeUser } from '@mcpmesh/auth-lib-react';

export default function Home() {
  const auth = useAuth();
  const meUser = useMeUser();

  if (auth.isLoading) {
    return <div className="text-slate-500">Loading…</div>;
  }

  if (auth.error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded p-4 text-red-800">
        Auth error: {auth.error.message}
      </div>
    );
  }

  if (!auth.isAuthenticated) {
    return (
      <div className="text-center py-16 space-y-6">
        <h1 className="text-4xl font-bold text-indigo-900">App One</h1>
        <p className="text-lg text-slate-600 max-w-xl mx-auto">
          Try the demo app. Click below to sign in via your tenant identity
          provider and view orders.
        </p>
        <button
          onClick={() => auth.signinRedirect()}
          className="bg-indigo-700 hover:bg-indigo-800 text-white px-6 py-3 rounded-lg text-base font-medium shadow"
        >
          Sign in
        </button>
      </div>
    );
  }

  // Prefer /me-derived identity; fall back to OIDC profile while the call is in flight.
  const name =
    meUser?.name ||
    meUser?.preferredUsername ||
    meUser?.email ||
    auth.user?.profile?.preferred_username ||
    auth.user?.profile?.email ||
    'friend';

  return (
    <div className="space-y-6">
      <div className="bg-white border rounded-lg p-6 shadow-sm">
        <h1 className="text-2xl font-semibold mb-2">Welcome, {name}</h1>
        <p className="text-slate-600">You're signed in to App One.</p>
      </div>
      <div className="flex gap-3">
        <Link
          to="/orders"
          className="bg-indigo-700 hover:bg-indigo-800 text-white px-4 py-2 rounded shadow-sm"
        >
          View orders
        </Link>
        {/*
         * UX-only gating: tenant-admins see a Manage users link that deep-links
         * to the admin-ui on this same host. The admin-ui detects the tenant
         * realm from window.location.hostname so SSO carries over. Backend
         * enforces actual authorisation; this is just a hint.
         */}
        <RequireRole role="tenant-admin">
          <a
            href={`${window.location.origin}/admin/`}
            className="bg-emerald-700 hover:bg-emerald-800 text-white px-4 py-2 rounded shadow-sm"
          >
            Manage users
          </a>
        </RequireRole>
        <button
          onClick={() => auth.signoutRedirect()}
          className="bg-white border border-slate-300 hover:bg-slate-100 text-slate-800 px-4 py-2 rounded"
        >
          Sign out
        </button>
      </div>
    </div>
  );
}
