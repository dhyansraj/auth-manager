// Single source of truth for dev-vs-prod detection in the admin UI (cosmetic
// chrome like the DEV badge). Platform base URLs are NOT derived from the
// host anymore — they come from GET /api/v1/bundle/bases (config-driven,
// same resolver as the downloadable onboarding bundle).

// Dev env hostnames: auth-dev.mcp-mesh.io (canonical single-host architecture
// mirroring prod), legacy admin-dev.* (since removed but kept for safety),
// and localhost (vite dev server).
export function isDevEnv(): boolean {
  const host = typeof window !== 'undefined' ? window.location.host : '';
  return host.startsWith('auth-dev.') || host.startsWith('admin-dev.') || host.startsWith('localhost');
}
