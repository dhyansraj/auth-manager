import type { UserManagerSettings } from 'oidc-client-ts';

/**
 * OIDC configuration derived from window.location at runtime — no env vars
 * baked into the bundle. Behaviour:
 *   - localhost / 127.0.0.1 → http://localhost:8180/realms/dev   (compose dev)
 *   - anywhere else         → ${origin}/auth/realms/dev          (k8s edge)
 *
 * The k8s edge serves Keycloak under /auth (KC_HOSTNAME=https://<host>/auth),
 * so the SPA's authority matches the iss claim KC mints.
 */
const isLocalhost =
  window.location.hostname === 'localhost' ||
  window.location.hostname === '127.0.0.1';

const authority = isLocalhost
  ? 'http://localhost:8180/realms/dev'
  : `${window.location.origin}/auth/realms/dev`;

export const oidcConfig: UserManagerSettings = {
  authority,
  client_id: 'auth-manager-ui',
  redirect_uri: `${window.location.origin}/auth/callback`,
  post_logout_redirect_uri: window.location.origin,
  response_type: 'code',
  scope: 'openid profile email',
  loadUserInfo: true,
  automaticSilentRenew: true,
};
