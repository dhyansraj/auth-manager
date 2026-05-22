import React from 'react';
import ReactDOM from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { AuthProvider } from 'react-oidc-context';
import { MeProvider } from '@mcpmesh/auth-lib-react';
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

// onSigninCallback: strip ?code and ?state from the URL after the SPA exchanges
// the auth code, so a refresh doesn't try to re-process the (already-used) code.
const onSigninCallback = () => {
  window.history.replaceState({}, document.title, window.location.pathname);
};

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AuthProvider {...oidcConfig} onSigninCallback={onSigninCallback}>
      <QueryClientProvider client={queryClient}>
        <MeProvider endpoint="/api/me">
          <BrowserRouter>
            <App />
          </BrowserRouter>
        </MeProvider>
      </QueryClientProvider>
    </AuthProvider>
  </React.StrictMode>
);
