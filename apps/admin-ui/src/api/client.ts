import { bffFetch } from '@mcpmesh/auth-lib-react';
import type {
  User,
  UserListResponse,
  CreateUserPayload,
  PermissionDto,
  RoleDto,
  CreateRoleRequest,
  UpdateRoleRequest,
  IdentityProviderDto,
  IdentityProviderId,
  ThemeMeta,
  ThemeRolloutStatus,
  BrandingConfig,
  DatabaseStatus,
  DatabaseProvisionResult,
} from './types';

// The admin-ui is served at /admin/* on every host. The edge maps
// /admin/api/v1/* → auth-manager (with /admin stripped at the proxy).
const base = '/admin/api/v1';

export class ApiError extends Error {
  status: number;
  body: unknown;
  constructor(status: number, statusText: string, body: unknown, raw: string) {
    super(`HTTP ${status} ${statusText}: ${raw}`);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

/**
 * Centralized 401 handling for admin-ui's API client. On 401, captures the
 * current path + query and redirects the browser to /_bff/login?redirect_back=...
 * The BFF sign-in flow round-trips back to the same URL with a fresh session.
 *
 * Wizard form state is persisted to sessionStorage by TenantWizard, so the
 * round-trip is non-destructive for in-progress onboarding.
 *
 * Throws after triggering the navigation so the calling promise chain halts —
 * no further code runs in the current request handler.
 */
async function checkAuth(r: Response): Promise<Response> {
  if (r.status === 401) {
    const back = window.location.pathname + window.location.search;
    // Use setTimeout to defer just enough for the throw to land first; the
    // navigation still happens because we haven't unloaded yet.
    setTimeout(() => {
      window.location.href = '/_bff/login?redirect_back=' + encodeURIComponent(back);
    }, 0);
    throw new ApiError(401, 'Session expired — redirecting to sign in', null, '');
  }
  return r;
}

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (!headers.has('Content-Type') && init.body) headers.set('Content-Type', 'application/json');

  const r = await bffFetch(base + path, { ...init, headers });
  await checkAuth(r);
  if (!r.ok) {
    const raw = await r.text();
    let parsed: unknown = raw;
    try { parsed = JSON.parse(raw); } catch { /* not JSON */ }
    throw new ApiError(r.status, r.statusText, parsed, raw);
  }
  if (r.status === 204) return undefined as T;
  return r.json() as Promise<T>;
}

export const api = {
  listTenants:   () => req<import('./types').Tenant[]>('/tenants'),
  getTenant:     (id: string) => req<import('./types').Tenant>(`/tenants/${id}`),
  getTenantBySlug: (slug: string) =>
    req<import('./types').Tenant>(`/tenants/by-slug/${slug}`),
  createTenant:  (body: {
    slug: string;
    displayName: string;
    adminEmail?: string;
    hostnames?: import('./types').HostnameAssignment[];
  }) =>
    req<import('./types').Tenant>('/tenants', { method: 'POST', body: JSON.stringify(body) }),
  deleteTenant:  (id: string) => req<void>(`/tenants/${id}`, { method: 'DELETE' }),
  retryTenant:   (id: string) => req<import('./types').Tenant>(`/tenants/${id}/retry`, { method: 'POST' }),
  listApps:      (tenantId: string) => req<import('./types').App[]>(`/tenants/${tenantId}/apps`),
  createApp:     (tenantId: string, body: {
    slug: string;
    displayName: string;
    profile?: 'CONFIDENTIAL_BACKEND' | 'SPA_PKCE' | 'SERVICE_ACCOUNT_ONLY';
    audience?: string[];
  }) =>
    req<import('./types').App & { clientSecret?: string | null }>(
      `/tenants/${tenantId}/apps`,
      { method: 'POST', body: JSON.stringify(body) }
    ),
  getServiceAccountPermissions: (tenantId: string, appId: string) =>
    req<{ permissions: string[] }>(
      `/tenants/${tenantId}/apps/${appId}/service-account/permissions`
    ),
  updateServiceAccountPermissions: (tenantId: string, appId: string, permissions: string[]) =>
    req<{ permissions: string[] }>(
      `/tenants/${tenantId}/apps/${appId}/service-account/permissions`,
      { method: 'PUT', body: JSON.stringify({ permissions }) }
    ),
  /**
   * Apply a manifest YAML to a tenant (UUID-keyed). Calls the new
   * /tenants/{id}/manifest:apply endpoint guarded by PERMISSIONS_EDIT.
   * The wizard + Permissions tab both route through here.
   */
  uploadManifest: async (tenantId: string, yamlBody: string) => {
    const r = await bffFetch(base + `/tenants/${tenantId}/manifest:apply?applyRoles=true`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-yaml' },
      body: yamlBody,
    });
    await checkAuth(r);
    if (!r.ok) {
      const raw = await r.text();
      let parsed: unknown = raw;
      try { parsed = JSON.parse(raw); } catch { /* not JSON */ }
      throw new ApiError(r.status, r.statusText, parsed, raw);
    }
    return r.json();
  },
  /**
   * Download the tenant's current manifest YAML. Pulls the file via blob +
   * synthetic anchor (same pattern as the onboarding bundle / theme starter
   * — direct <a download> doesn't reliably attach the session cookie).
   */
  downloadManifest: async (tenantId: string): Promise<void> => {
    // Explicit Accept: defensive. Without it browsers send `*/*` and Spring's
    // content negotiation can mis-route to the slug-keyed manifest controller.
    const r = await bffFetch(`${base}/tenants/${tenantId}/manifest`, {
      credentials: 'include',
      headers: { Accept: 'application/x-yaml' },
    });
    await checkAuth(r);
    if (!r.ok) throw new ApiError(r.status, r.statusText, null, await r.text());
    const blob = await r.blob();
    const filename = r.headers.get('Content-Disposition')?.match(/filename="(.+?)"/)?.[1]
      || `${tenantId}-manifest.yaml`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
  updateRoutes: (slug: string, body: { targets: Record<string, string>; rules: Array<{ path: string; authMode: 'PUBLIC' | 'REQUIRED' | 'OPTIONAL'; target: string }> }) =>
    req<import('./types').RoutingConfig>(`/tenants/${slug}/routes`, {
      method: 'PUT',
      body: JSON.stringify(body),
    }),
  deleteApp:     (tenantId: string, appId: string) => req<void>(`/tenants/${tenantId}/apps/${appId}`, { method: 'DELETE' }),
  globalAudit:   (page = 0, size = 50) => req<import('./types').PageResponse<import('./types').AuditEvent>>(`/audit?page=${page}&size=${size}`),
  tenantAudit:   (tenantId: string, page = 0, size = 50) =>
    req<import('./types').PageResponse<import('./types').AuditEvent>>(`/tenants/${tenantId}/audit?page=${page}&size=${size}`),
  listUsers: (tenantId: string, search?: string, first = 0, max = 50) => {
    const qs = new URLSearchParams();
    if (search) qs.set('search', search);
    qs.set('first', String(first));
    qs.set('max', String(max));
    return req<UserListResponse>(`/tenants/${tenantId}/users?${qs}`);
  },
  getUser:    (tenantId: string, userId: string) => req<User>(`/tenants/${tenantId}/users/${userId}`),
  createUser: (tenantId: string, body: CreateUserPayload) =>
    req<User>(`/tenants/${tenantId}/users`, { method: 'POST', body: JSON.stringify(body) }),
  disableUser:(tenantId: string, userId: string) =>
    req<void>(`/tenants/${tenantId}/users/${userId}`, { method: 'DELETE' }),
  resendInvite: (tenantId: string, userId: string) =>
    req<void>(`/tenants/${tenantId}/users/${userId}/invite`, { method: 'POST' }),
  getRoutes: (slug: string) =>
    req<import('./types').RoutingConfig>(`/tenants/${slug}/routes`),
  replaceRoutes: (slug: string, body: import('./types').RoutingConfig) =>
    req<import('./types').RoutingConfig>(`/tenants/${slug}/routes`, {
      method: 'PUT', body: JSON.stringify(body)
    }),

  // -------------------------------------------------------------------------
  // Custom Roles: permissions catalog + composite-role CRUD (slug-keyed)
  // -------------------------------------------------------------------------
  listPermissions: (slug: string) =>
    req<PermissionDto[]>(`/tenants/${slug}/permissions`),
  listRoles: (slug: string) =>
    req<RoleDto[]>(`/tenants/${slug}/roles`),
  createRole: (slug: string, body: CreateRoleRequest) =>
    req<RoleDto>(`/tenants/${slug}/roles`, { method: 'POST', body: JSON.stringify(body) }),
  updateRole: (slug: string, name: string, body: UpdateRoleRequest) =>
    req<RoleDto>(`/tenants/${slug}/roles/${encodeURIComponent(name)}`, {
      method: 'PUT', body: JSON.stringify(body)
    }),
  deleteRole: (slug: string, name: string) =>
    req<void>(`/tenants/${slug}/roles/${encodeURIComponent(name)}`, { method: 'DELETE' }),

  /** Slug-keyed: returns both client `roles` and composite `realmRoles`. */
  getUserBySlug: (slug: string, userId: string) =>
    req<User>(`/tenants/${slug}/users/${userId}`),
  /**
   * Atomic-replace the user's role assignments. {@code realmRoles} is the
   * full desired set of composite (custom) role names. {@code systemRoles}
   * is OPTIONAL — when present, the manageable system client roles
   * (tenant-admin, tenant-user-manager) are reconciled too; omit to leave
   * them untouched. The user-viewer baseline is always preserved by the
   * backend and is never exposed in the UI.
   *
   * <p>Backend authorization: the privileged systemRoles path requires
   * canManageTenant (tenant-admin or platform-admin); plain realmRoles
   * updates allow canManageUsersInTenant (also tenant-user-manager).
   */
  updateUserRoles: (
    slug: string,
    userId: string,
    payload: { realmRoles: string[]; systemRoles?: string[] }
  ) =>
    req<User>(`/tenants/${slug}/users/${userId}/roles`, {
      method: 'PUT',
      body: JSON.stringify({
        roleNames: payload.realmRoles,
        ...(payload.systemRoles !== undefined ? { systemRoles: payload.systemRoles } : {}),
      }),
    }),

  // -------------------------------------------------------------------------
  // Identity Providers: per-tenant Google + GitHub social-login toggle
  // -------------------------------------------------------------------------
  listIdentityProviders: (slug: string) =>
    req<IdentityProviderDto[]>(`/tenants/${slug}/identity-providers`),
  setIdentityProviderEnabled: (slug: string, providerId: IdentityProviderId, enabled: boolean) =>
    req<IdentityProviderDto>(`/tenants/${slug}/identity-providers/${providerId}`, {
      method: 'PUT', body: JSON.stringify({ enabled })
    }),

  // -------------------------------------------------------------------------
  // Branding / Custom Themes
  // -------------------------------------------------------------------------
  /** Returns the URL to the starter zip; consumer should set window.location to it. */
  themeStarterUrl: (slug: string) => `${base}/tenants/${slug}/theme/starter`,
  getThemeMeta: (slug: string) => req<ThemeMeta>(`/tenants/${slug}/theme`),
  uploadTheme: async (slug: string, file: File): Promise<ThemeMeta> => {
    // Do NOT set Content-Type — the browser sets multipart boundary itself.
    // bffFetch attaches cookies + the X-CSRF-Token header automatically.
    const form = new FormData();
    form.append('file', file);
    const r = await bffFetch(`${base}/tenants/${slug}/theme`, {
      method: 'POST', body: form,
    });
    await checkAuth(r);
    if (!r.ok) {
      const raw = await r.text();
      let parsed: unknown = raw;
      try { parsed = JSON.parse(raw); } catch { /* not JSON */ }
      throw new ApiError(r.status, r.statusText, parsed, raw);
    }
    return r.json() as Promise<ThemeMeta>;
  },
  deleteTheme: (slug: string) =>
    req<void>(`/tenants/${slug}/theme`, { method: 'DELETE' }),
  getThemeStatus: (slug: string) =>
    req<ThemeRolloutStatus>(`/tenants/${slug}/theme/status`),

  // -------------------------------------------------------------------------
  // Rich-login Branding (layout variant + named slot HTML)
  // -------------------------------------------------------------------------
  getBranding: (slug: string) =>
    req<BrandingConfig>(`/tenants/${slug}/branding`),
  updateBranding: (slug: string, body: BrandingConfig) =>
    req<BrandingConfig>(`/tenants/${slug}/branding`, {
      method: 'PUT', body: JSON.stringify(body),
    }),

  // -------------------------------------------------------------------------
  // Data Services / Managed Postgres
  // -------------------------------------------------------------------------
  getDatabaseStatus: (tenantId: string) =>
    req<DatabaseStatus>(`/tenants/${tenantId}/data/postgres`),
  provisionDatabase: (tenantId: string) =>
    req<DatabaseProvisionResult>(`/tenants/${tenantId}/data/postgres`, { method: 'POST' }),
  deprovisionDatabase: (tenantId: string) =>
    req<void>(`/tenants/${tenantId}/data/postgres`, { method: 'DELETE' }),

  // -------------------------------------------------------------------------
  // Onboarding bundle (.zip handoff for tenant teams)
  // -------------------------------------------------------------------------
  downloadOnboardingBundle: async (tenantId: string): Promise<void> => {
    const r = await bffFetch(`${base}/tenants/${tenantId}/onboarding-bundle`, {
      credentials: 'include',
    });
    await checkAuth(r);
    if (!r.ok) throw new ApiError(r.status, r.statusText, null, await r.text());
    const blob = await r.blob();
    const filename = r.headers.get('Content-Disposition')?.match(/filename="(.+?)"/)?.[1]
      || 'onboarding-bundle.zip';
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};
