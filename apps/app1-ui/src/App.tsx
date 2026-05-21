import { Link, NavLink, Route, Routes } from 'react-router-dom';
import { useAuth } from 'react-oidc-context';
import Home from './pages/Home';
import Orders from './pages/Orders';

export default function App() {
  const auth = useAuth();
  return (
    <div className="min-h-screen flex flex-col">
      <header className="bg-indigo-900 text-indigo-50 px-6 py-3 flex items-center justify-between">
        <Link to="/" className="text-lg font-semibold">App One</Link>
        <nav className="flex gap-4 text-sm items-center">
          <NavLink to="/" end className={({isActive}) => isActive ? 'text-white' : 'text-indigo-200 hover:text-white'}>Home</NavLink>
          <NavLink to="/orders" className={({isActive}) => isActive ? 'text-white' : 'text-indigo-200 hover:text-white'}>Orders</NavLink>
          <span className="mx-2 text-indigo-700">|</span>
          {auth.isLoading ? (
            <span className="text-indigo-200 text-xs">checking…</span>
          ) : auth.isAuthenticated ? (
            <>
              <span className="text-indigo-200 text-xs">
                {auth.user?.profile?.preferred_username || auth.user?.profile?.email || 'signed in'}
              </span>
              <button onClick={() => auth.signoutRedirect()}
                      className="text-indigo-200 hover:text-white text-xs underline">Sign out</button>
            </>
          ) : (
            <button onClick={() => auth.signinRedirect()}
                    className="bg-white text-indigo-900 px-3 py-1 rounded text-xs hover:bg-indigo-100">
              Sign in
            </button>
          )}
        </nav>
      </header>
      <main className="flex-1 max-w-5xl w-full mx-auto px-6 py-8">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/orders" element={<Orders />} />
        </Routes>
      </main>
    </div>
  );
}
