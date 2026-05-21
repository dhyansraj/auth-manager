import type { UserManagerSettings } from 'oidc-client-ts';

/**
 * OIDC config derived from window.location at runtime — no baked env vars.
 *   - localhost / 127.0.0.1 → http://localhost:8180/realms/dev (compose dev)
 *   - anywhere else         → https://auth.mcp-mesh.io/auth/realms/t-app1
 *
 * For the deployed app the SPA always points at the live platform's
 * tenant realm. The k8s edge serves Keycloak under /auth.
 */
const isLocalhost =
  window.location.hostname === 'localhost' ||
  window.location.hostname === '127.0.0.1';

const authority = isLocalhost
  ? 'http://localhost:8180/realms/dev'
  : 'https://auth.mcp-mesh.io/auth/realms/t-app1';

export const oidcConfig: UserManagerSettings = {
  authority,
  client_id: 'app1-ui',
  redirect_uri: `${window.location.origin}/`,
  post_logout_redirect_uri: window.location.origin,
  response_type: 'code',
  scope: 'openid profile email',
  loadUserInfo: true,
  automaticSilentRenew: true,
};
