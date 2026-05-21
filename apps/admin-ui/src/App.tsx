import { Link, NavLink, Route, Routes } from 'react-router-dom';
import { useAuth } from 'react-oidc-context';
import Dashboard from './pages/Dashboard';
import TenantsList from './pages/TenantsList';
import TenantDetail from './pages/TenantDetail';
import AuditLog from './pages/AuditLog';
import AuthCallback from './auth/AuthCallback';
import AuthTokenSync from './auth/AuthTokenSync';

export default function App() {
  const auth = useAuth();
  return (
    <div className="min-h-screen flex flex-col">
      <header className="bg-slate-900 text-slate-100 px-6 py-3 flex items-center justify-between">
        <Link to="/" className="text-lg font-semibold">auth-manager</Link>
        <nav className="flex gap-4 text-sm items-center">
          <NavLink to="/" end className={({isActive}) => isActive ? 'text-white' : 'text-slate-300 hover:text-white'}>Dashboard</NavLink>
          <NavLink to="/tenants" className={({isActive}) => isActive ? 'text-white' : 'text-slate-300 hover:text-white'}>Tenants</NavLink>
          <NavLink to="/audit" className={({isActive}) => isActive ? 'text-white' : 'text-slate-300 hover:text-white'}>Audit</NavLink>
          <span className="mx-2 text-slate-600">|</span>
          {auth.isLoading ? (
            <span className="text-slate-400 text-xs">checking…</span>
          ) : auth.isAuthenticated ? (
            <>
              <span className="text-slate-300 text-xs">
                {auth.user?.profile?.preferred_username || auth.user?.profile?.email || 'signed in'}
              </span>
              <button onClick={() => auth.signoutRedirect()}
                      className="text-slate-300 hover:text-white text-xs underline">Sign out</button>
            </>
          ) : (
            <button onClick={() => auth.signinRedirect()}
                    className="bg-white text-slate-900 px-3 py-1 rounded text-xs hover:bg-slate-200">
              Sign in
            </button>
          )}
        </nav>
      </header>
      <main className="flex-1 max-w-6xl w-full mx-auto px-6 py-6">
        <AuthTokenSync />
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/tenants" element={<TenantsList />} />
          <Route path="/tenants/:id" element={<TenantDetail />} />
          <Route path="/audit" element={<AuditLog />} />
          <Route path="/auth/callback" element={<AuthCallback />} />
        </Routes>
      </main>
    </div>
  );
}
