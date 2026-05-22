import { createOidcConfig } from '@mcpmesh/auth-lib-react';

/**
 * OIDC configuration derived from window.location at runtime — no env vars
 * baked into the bundle.
 *
 * The admin-ui is served at /admin/* on BOTH the platform host
 * (auth.mcp-mesh.io) AND on tenant subdomains (e.g. app1.mcp-mesh.io). The
 * realm to authenticate against is picked from the hostname:
 *   - localhost / 127.0.0.1       → realm 'dev' on http://localhost:8180
 *   - auth.mcp-mesh.io             → realm 'dev' (platform-admin)
 *   - app1.mcp-mesh.io             → realm 't-app1' (tenant-admin SSO)
 *   - <slug>.mcp-mesh.io           → realm 't-<slug>' (default convention)
 *
 * The k8s edge serves Keycloak under /auth on every host
 * (KC_HOSTNAME=https://auth.mcp-mesh.io/auth), so tenant-host pages' authority
 * still points back to auth.mcp-mesh.io.
 */
export const oidcConfig = createOidcConfig({
  clientId: 'usermanagement',
  hostToRealm: {
    'auth.mcp-mesh.io': 'dev',
  },
  redirectUri: `${window.location.origin}/admin/`,
  postLogoutRedirectUri: `${window.location.origin}/admin/`,
});
