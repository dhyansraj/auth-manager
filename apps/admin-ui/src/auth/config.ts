import type { UserManagerSettings } from 'oidc-client-ts';

/**
 * OIDC configuration. For dev we hardcode the dev realm + auth-manager-ui
 * client. When the UI gets served at users.<tenant>.com we'll switch to a
 * dynamic config derived from hostname (next commit).
 */
export const oidcConfig: UserManagerSettings = {
  authority: 'http://localhost:8180/realms/dev',
  client_id: 'auth-manager-ui',
  redirect_uri: `${window.location.origin}/auth/callback`,
  post_logout_redirect_uri: window.location.origin,
  response_type: 'code',
  scope: 'openid profile email',
  loadUserInfo: true,
  automaticSilentRenew: true,
};
