import { Link, NavLink, Route, Routes } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import TenantsList from './pages/TenantsList';
import TenantDetail from './pages/TenantDetail';
import AuditLog from './pages/AuditLog';

export default function App() {
  return (
    <div className="min-h-screen flex flex-col">
      <header className="bg-slate-900 text-slate-100 px-6 py-3 flex items-center justify-between">
        <Link to="/" className="text-lg font-semibold">auth-manager</Link>
        <nav className="flex gap-4 text-sm">
          <NavLink to="/" end className={({isActive}) => isActive ? 'text-white' : 'text-slate-300 hover:text-white'}>Dashboard</NavLink>
          <NavLink to="/tenants" className={({isActive}) => isActive ? 'text-white' : 'text-slate-300 hover:text-white'}>Tenants</NavLink>
          <NavLink to="/audit" className={({isActive}) => isActive ? 'text-white' : 'text-slate-300 hover:text-white'}>Audit</NavLink>
        </nav>
      </header>
      <main className="flex-1 max-w-6xl w-full mx-auto px-6 py-6">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/tenants" element={<TenantsList />} />
          <Route path="/tenants/:id" element={<TenantDetail />} />
          <Route path="/audit" element={<AuditLog />} />
        </Routes>
      </main>
    </div>
  );
}
