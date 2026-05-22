import { createOidcConfig } from '@mcpmesh/auth-lib-react';

/**
 * OIDC config derived from window.location at runtime — no baked env vars.
 *   - localhost / 127.0.0.1 → http://localhost:8180/realms/dev (compose dev)
 *   - app1.mcp-mesh.io      → https://auth.mcp-mesh.io/auth/realms/t-app1
 *   - <slug>.mcp-mesh.io    → https://auth.mcp-mesh.io/auth/realms/t-<slug>
 *
 * The k8s edge serves Keycloak under /auth on the platform host
 * (auth.mcp-mesh.io), so all tenant-host pages still point their OIDC
 * authority back there.
 */
export const oidcConfig = createOidcConfig({
  clientId: 'app1-ui',
  hostToRealm: {
    'app1.mcp-mesh.io': 't-app1',
  },
});
