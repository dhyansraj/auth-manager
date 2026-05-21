import React from 'react';
import ReactDOM from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { AuthProvider } from 'react-oidc-context';
import App from './App';
import { oidcConfig } from './auth/config';
import './index.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      refetchOnWindowFocus: false,
    },
  },
});

// vite's BASE_URL is '/admin/' here; React Router wants a basename without
// the trailing slash (so '/admin' for routes like '/admin/tenants').
const basename = import.meta.env.BASE_URL.replace(/\/$/, '');

// onSigninCallback: strip ?code and ?state from the URL after the SPA exchanges
// the auth code, so a refresh doesn't try to re-process the (already-used) code.
// The redirect_uri lands on /admin/ (the dashboard), so we keep the pathname.
const onSigninCallback = () => {
  window.history.replaceState({}, document.title, window.location.pathname);
};

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AuthProvider {...oidcConfig} onSigninCallback={onSigninCallback}>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter basename={basename}>
          <App />
        </BrowserRouter>
      </QueryClientProvider>
    </AuthProvider>
  </React.StrictMode>
);
