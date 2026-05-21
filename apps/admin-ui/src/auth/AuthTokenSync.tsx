import { useEffect } from 'react';
import { useAuth } from 'react-oidc-context';
import { setAccessToken } from '../api/client';

export default function AuthTokenSync() {
  const auth = useAuth();
  useEffect(() => {
    setAccessToken(auth.isAuthenticated && auth.user ? auth.user.access_token : null);
  }, [auth.isAuthenticated, auth.user]);
  return null;
}
