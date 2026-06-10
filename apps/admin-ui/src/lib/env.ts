// Single source of truth for dev-vs-prod detection in the admin UI, plus the
// env-specific base URLs rendered on screen (wizard env-var snippet, broker
// redirect URIs). The downloadable onboarding bundle is generated server-side
// with its own env-correct values — if the cluster/host layout changes, update
// it there too.

// Dev env hostnames: auth-dev.mcp-mesh.io (canonical single-host architecture
// mirroring prod), legacy admin-dev.* (since removed but kept for safety),
// and localhost (vite dev server).
export function isDevEnv(): boolean {
  const host = typeof window !== 'undefined' ? window.location.host : '';
  return host.startsWith('auth-dev.') || host.startsWith('admin-dev.') || host.startsWith('localhost');
}

export interface BundleBases {
  /** Keycloak public base, e.g. https://auth.mcp-mesh.io/auth */
  kcBase: string;
  /** auth-manager's in-cluster service URL (what tenant backends call) */
  authMgrInClusterBase: string;
}

export function bundleBases(): BundleBases {
  return isDevEnv()
    ? {
        kcBase: 'https://auth-dev.mcp-mesh.io/auth',
        authMgrInClusterBase:
          'http://auth-platform-dev-auth-manager.auth-platform-dev.svc.cluster.local:8080',
      }
    : {
        kcBase: 'https://auth.mcp-mesh.io/auth',
        authMgrInClusterBase:
          'http://auth-platform-auth-manager.auth-platform.svc.cluster.local:8080',
      };
}
