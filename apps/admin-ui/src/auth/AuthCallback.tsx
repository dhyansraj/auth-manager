import { useAuth } from 'react-oidc-context';
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export default function AuthCallback() {
  const auth = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!auth.isLoading && auth.isAuthenticated) navigate('/', { replace: true });
    if (auth.error) console.error('OIDC error:', auth.error);
  }, [auth.isLoading, auth.isAuthenticated, auth.error, navigate]);

  if (auth.error) return <div className="p-6 text-red-700">Auth error: {auth.error.message}</div>;
  return <div className="p-6 text-slate-500">Finishing sign-in…</div>;
}
