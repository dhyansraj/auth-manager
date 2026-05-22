import { Link, NavLink, Route, Routes, BrowserRouter } from 'react-router-dom';
import { useAuth } from 'react-oidc-context';
import { MeProvider, useCurrentTenant } from '@mcpmesh/auth-lib-react';
import Dashboard from './pages/Dashboard';
import TenantsList from './pages/TenantsList';
import TenantDetail from './pages/TenantDetail';
import AuditLog from './pages/AuditLog';
import AuthTokenSync from './auth/AuthTokenSync';

// vite's BASE_URL is '/admin/' here; React Router wants a basename without
// the trailing slash (so '/admin' for routes like '/admin/tenants').
const basename = import.meta.env.BASE_URL.replace(/\/$/, '');

function SplashLoading() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50">
      <div className="text-slate-500 text-sm">Loading…</div>
    </div>
  );
}

function SignInPage() {
  const auth = useAuth();
  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50">
      <div className="text-center space-y-6 max-w-md px-6">
        <div className="space-y-2">
          <h1 className="text-4xl font-bold text-slate-900 tracking-tight">auth-manager</h1>
          <p className="text-slate-600 text-lg">Sign in to manage your tenant.</p>
        </div>
        <button
          onClick={() => auth.signinRedirect()}
          className="bg-slate-900 hover:bg-slate-800 text-white px-10 py-4 rounded-lg shadow text-lg font-medium"
        >
          Sign in
        </button>
      </div>
    </div>
  );
}

// Inline placement keeps the header to a single row and reads cleaner alongside
// the branding (vs. stacking which adds vertical noise).
function BackToAppLink() {
  const isPlatformHost = window.location.hostname === 'auth.mcp-mesh.io';
  const tenant = useCurrentTenant();
  if (isPlatformHost) return null;
  const appName = tenant?.displayName ?? window.location.hostname.split('.')[0];
  return (
    <a
      href={`${window.location.origin}/`}
      className="text-slate-400 hover:text-white text-sm flex items-center gap-1"
    >
      <span aria-hidden>←</span> Back to {appName}
    </a>
  );
}

function AuthenticatedShell() {
  const auth = useAuth();
  return (
    <BrowserRouter basename={basename}>
      <div className="min-h-screen flex flex-col">
        <header className="bg-slate-900 text-slate-100 px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link to="/" className="text-lg font-semibold">auth-manager</Link>
            <BackToAppLink />
          </div>
          <nav className="flex gap-4 text-sm items-center">
            <NavLink to="/" end className={({isActive}) => isActive ? 'text-white' : 'text-slate-300 hover:text-white'}>Dashboard</NavLink>
            <NavLink to="/tenants" className={({isActive}) => isActive ? 'text-white' : 'text-slate-300 hover:text-white'}>Tenants</NavLink>
            <NavLink to="/audit" className={({isActive}) => isActive ? 'text-white' : 'text-slate-300 hover:text-white'}>Audit</NavLink>
            <span className="mx-2 text-slate-600">|</span>
            <span className="text-slate-300 text-xs">
              {auth.user?.profile?.preferred_username || auth.user?.profile?.email || 'signed in'}
            </span>
            <button onClick={() => auth.signoutRedirect()}
                    className="text-slate-300 hover:text-white text-xs underline">Sign out</button>
          </nav>
        </header>
        <main className="flex-1 max-w-6xl w-full mx-auto px-6 py-6">
          <AuthTokenSync />
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/tenants" element={<TenantsList />} />
            <Route path="/tenants/:id" element={<TenantDetail />} />
            <Route path="/audit" element={<AuditLog />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default function App() {
  const auth = useAuth();
  if (auth.isLoading) return <SplashLoading />;
  if (!auth.isAuthenticated) return <SignInPage />;
  // MeProvider only mounts after auth — otherwise /me 401s on the splash screen.
  return (
    <MeProvider endpoint="/admin/api/v1/me">
      <AuthenticatedShell />
    </MeProvider>
  );
}
