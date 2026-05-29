/**
 * Minimal `User` shape we forward to user-supplied onSigninCallback. We don't
 * import oidc-client-ts' type to avoid pulling that into the public API
 * surface; the shape is whatever react-oidc-context hands AuthProviderProps'
 * onSigninCallback anyway (i.e. an oidc-client-ts User | void).
 */
type SigninCallbackUser = unknown;

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
  /**
   * Optional user callback invoked AFTER the lib's default URL-stripping logic.
   * Useful for analytics / post-login navigation. If you need full control,
   * pass a callback here — the URL strip happens before it runs.
   *
   * To OPT OUT of the URL strip entirely, pass `disableDefaultUrlStrip: true`
   * and provide your own callback (or pass `() => {}` to no-op).
   */
  onSigninCallback?: (user: SigninCallbackUser) => void;
  /**
   * Disable the default URL-strip behavior. Default false. See `onSigninCallback`
   * for context. You normally want the default ON — otherwise a page refresh
   * after PKCE return re-submits the spent code and silently fails.
   */
  disableDefaultUrlStrip?: boolean;
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
  /**
   * Strips `?code=...&state=...&iss=...&session_state=...` from the URL after
   * the PKCE return so a refresh doesn't re-submit the spent code. If the
   * caller passed their own `onSigninCallback` in options, ours runs first
   * (URL strip), then theirs. Set `disableDefaultUrlStrip: true` to bypass.
   */
  onSigninCallback: (user: SigninCallbackUser) => void;
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

  const userCallback = opts.onSigninCallback;
  const stripDisabled = opts.disableDefaultUrlStrip === true;
  const onSigninCallback = (user: SigninCallbackUser): void => {
    if (!stripDisabled && typeof window !== 'undefined' && window.history?.replaceState) {
      window.history.replaceState({}, document.title, window.location.pathname);
    }
    if (userCallback) userCallback(user);
  };

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
    onSigninCallback,
  };
}
