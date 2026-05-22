export interface CreateOidcConfigOptions {
  /** Map of hostname -> OIDC realm. e.g. { 'auth.mcp-mesh.io': 'dev', 'app1.mcp-mesh.io': 't-app1' } */
  hostToRealm?: Record<string, string>;
  /** Function called when no host matches — receives hostname, returns realm name. */
  fallbackRealm?: (hostname: string) => string;
  /** Default for localhost dev. */
  localhostRealm?: string;
  /** Default for localhost dev. */
  localhostAuthority?: string;
  clientId: string;
  /** Where to send the user after login. Defaults to window.location.origin + '/'. */
  redirectUri?: string;
  /** Where to send the user after logout. Defaults to redirectUri. */
  postLogoutRedirectUri?: string;
  /** Override the OIDC config base. Defaults to 'https://auth.mcp-mesh.io/auth'. */
  authBase?: string;
}

export interface OidcConfig {
  authority: string;
  client_id: string;
  redirect_uri: string;
  post_logout_redirect_uri: string;
  response_type: 'code';
  scope: string;
  automaticSilentRenew: boolean;
  monitorSession: boolean;
  loadUserInfo: boolean;
}

export function createOidcConfig(opts: CreateOidcConfigOptions): OidcConfig {
  const host = window.location.hostname;
  const isLocalhost = host === 'localhost' || host === '127.0.0.1';
  const authBase = opts.authBase ?? 'https://auth.mcp-mesh.io/auth';

  let authority: string;
  if (isLocalhost) {
    authority =
      opts.localhostAuthority ??
      `http://localhost:8180/realms/${opts.localhostRealm ?? 'dev'}`;
  } else if (opts.hostToRealm?.[host]) {
    authority = `${authBase}/realms/${opts.hostToRealm[host]}`;
  } else if (opts.fallbackRealm) {
    authority = `${authBase}/realms/${opts.fallbackRealm(host)}`;
  } else {
    // Default convention: <slug>.mcp-mesh.io -> t-<slug>
    const slug = host.split('.')[0];
    authority = `${authBase}/realms/t-${slug}`;
  }

  const redirectUri = opts.redirectUri ?? `${window.location.origin}/`;
  return {
    authority,
    client_id: opts.clientId,
    redirect_uri: redirectUri,
    post_logout_redirect_uri: opts.postLogoutRedirectUri ?? redirectUri,
    response_type: 'code',
    scope: 'openid profile email',
    automaticSilentRenew: true,
    monitorSession: false,
    loadUserInfo: false,
  };
}
