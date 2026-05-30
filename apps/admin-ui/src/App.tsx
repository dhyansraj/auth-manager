import { Link, NavLink, Route, Routes, BrowserRouter } from 'react-router-dom';
import { BffAutoSignIn, MeProvider, useBffAuth, useCurrentTenant } from '@mcpmesh/auth-lib-react';
import Dashboard from './pages/Dashboard';
import TenantsList from './pages/TenantsList';
import TenantWizard from './pages/TenantWizard';
import TenantDetail from './pages/TenantDetail';
import AuditLog from './pages/AuditLog';

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

// Surfaces a "DEV" pill next to the brand on dev/local hosts so operators
// running both envs side-by-side can tell at a glance which one they're
// looking at. Absence-of-badge = production; intentional, keeps prod chrome
// clean.
function EnvBadge() {
  const host = typeof window !== 'undefined' ? window.location.host : '';
  // Dev env hostnames: auth-dev.mcp-mesh.io (canonical single-host architecture
  // mirroring prod), legacy admin-dev.* (since removed but kept for safety),
  // and localhost (vite dev server).
  if (host.startsWith('auth-dev.') || host.startsWith('admin-dev.') || host.startsWith('localhost')) {
    return (
      <span className="ml-2 inline-flex items-center rounded-md bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800 ring-1 ring-inset ring-amber-200">
        DEV
      </span>
    );
  }
  return null;
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

// Account console URL is realm-specific: dev realm on the platform host,
// t-<slug> on tenant subdomains. KC serves the account console at
// /auth/realms/<realm>/account regardless of admin-ui's base path.
function AccountConsoleLink() {
  const isPlatformHost = window.location.hostname === 'auth.mcp-mesh.io';
  const tenant = useCurrentTenant();
  const realm = isPlatformHost ? 'dev' : (tenant?.realmName ?? `t-${window.location.hostname.split('.')[0]}`);
  return (
    <a
      href={`${window.location.origin}/auth/realms/${realm}/account`}
      target="_blank"
      rel="noopener"
      className="text-slate-300 hover:text-white text-xs underline"
      title="Change password, configure OTP, view sessions"
    >
      My account
    </a>
  );
}

function AuthenticatedShell() {
  const auth = useBffAuth();
  return (
    <BrowserRouter basename={basename}>
      <div className="min-h-screen flex flex-col">
        <header className="bg-slate-900 text-slate-100 px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex items-center">
              <Link to="/" className="text-lg font-semibold">auth-manager</Link>
              <EnvBadge />
            </div>
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
            <AccountConsoleLink />
            <button onClick={() => auth.signoutRedirect()}
                    className="text-slate-300 hover:text-white text-xs underline">Sign out</button>
          </nav>
        </header>
        <main className="flex-1 max-w-6xl w-full mx-auto px-6 py-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/tenants" element={<TenantsList />} />
            <Route path="/tenants/new" element={<TenantWizard />} />
            <Route path="/tenants/:id" element={<TenantDetail />} />
            <Route path="/audit" element={<AuditLog />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default function App() {
  const auth = useBffAuth();
  if (auth.isLoading) return <SplashLoading />;
  if (!auth.isAuthenticated) return <BffAutoSignIn heading="auth-manager" subtitle="Signing in to your tenant…" />;
  // MeProvider only mounts after auth — otherwise /me 401s on the splash screen.
  return (
    <MeProvider endpoint="/admin/api/v1/me" authMode="cookie">
      <AuthenticatedShell />
    </MeProvider>
  );
}
