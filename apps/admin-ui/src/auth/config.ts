import type { UserManagerSettings } from 'oidc-client-ts';

/**
 * OIDC configuration derived from window.location at runtime — no env vars
 * baked into the bundle.
 *
 * The admin-ui is served at /admin/* on BOTH the platform host
 * (auth.mcp-mesh.io) AND on tenant subdomains (e.g. app1.mcp-mesh.io). The
 * realm to authenticate against is picked from the hostname:
 *   - localhost / 127.0.0.1       → realm 'dev' on http://localhost:8180
 *                                    (compose dev — platform host)
 *   - auth.mcp-mesh.io             → realm 'dev' (platform-admin)
 *   - app1.mcp-mesh.io             → realm 't-app1' (tenant-admin SSO)
 *
 * The k8s edge serves Keycloak under /auth on every host
 * (KC_HOSTNAME=https://auth.mcp-mesh.io/auth), so tenant-host pages authority
 * still points back to auth.mcp-mesh.io.
 */
const PLATFORM_HOST = 'auth.mcp-mesh.io';
const PLATFORM_REALM = 'dev';

function resolveRealm(): { authority: string; isPlatformHost: boolean } {
  const host = window.location.hostname;
  if (host === 'localhost' || host === '127.0.0.1') {
    return {
      authority: `http://localhost:8180/realms/${PLATFORM_REALM}`,
      isPlatformHost: true,
    };
  }
  if (host === PLATFORM_HOST) {
    return {
      authority: `${window.location.origin}/auth/realms/${PLATFORM_REALM}`,
      isPlatformHost: true,
    };
  }
  // Tenant subdomain — e.g. app1.mcp-mesh.io → realm 't-app1'.
  // The KC issuer always lives on the platform host under /auth.
  const slug = host.split('.')[0];
  return {
    authority: `https://${PLATFORM_HOST}/auth/realms/t-${slug}`,
    isPlatformHost: false,
  };
}

const resolved = resolveRealm();

export const isPlatformHost = resolved.isPlatformHost;

export const oidcConfig: UserManagerSettings = {
  authority: resolved.authority,
  client_id: 'usermanagement',
  redirect_uri: `${window.location.origin}/admin/`,
  post_logout_redirect_uri: `${window.location.origin}/admin/`,
  response_type: 'code',
  scope: 'openid profile email',
  loadUserInfo: true,
  automaticSilentRenew: true,
};
