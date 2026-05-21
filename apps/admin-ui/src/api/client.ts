import type { User, UserListResponse, CreateUserPayload } from './types';

// The admin-ui is served at /admin/* on every host. The edge maps
// /admin/api/v1/* → auth-manager (with /admin stripped at the proxy).
const base = '/admin/api/v1';

// Module-level token holder; set by AuthTokenSync on every auth state change.
let accessToken: string | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (!headers.has('Content-Type') && init.body) headers.set('Content-Type', 'application/json');
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);

  const r = await fetch(base + path, { ...init, headers });
  if (!r.ok) {
    const body = await r.text();
    throw new Error(`HTTP ${r.status} ${r.statusText}: ${body}`);
  }
  if (r.status === 204) return undefined as T;
  return r.json() as Promise<T>;
}

export const api = {
  listTenants:   () => req<import('./types').Tenant[]>('/tenants'),
  getTenant:     (id: string) => req<import('./types').Tenant>(`/tenants/${id}`),
  createTenant:  (body: { slug: string; displayName: string; hostnames?: import('./types').HostnameAssignment[] }) =>
    req<import('./types').Tenant>('/tenants', { method: 'POST', body: JSON.stringify(body) }),
  deleteTenant:  (id: string) => req<void>(`/tenants/${id}`, { method: 'DELETE' }),
  retryTenant:   (id: string) => req<import('./types').Tenant>(`/tenants/${id}/retry`, { method: 'POST' }),
  listApps:      (tenantId: string) => req<import('./types').App[]>(`/tenants/${tenantId}/apps`),
  createApp:     (tenantId: string, body: { slug: string; displayName: string }) =>
    req<import('./types').App>(`/tenants/${tenantId}/apps`, { method: 'POST', body: JSON.stringify(body) }),
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
  updateUserRoles: (tenantId: string, userId: string, roles: string[]) =>
    req<User>(`/tenants/${tenantId}/users/${userId}/roles`, {
      method: 'PUT', body: JSON.stringify({ roles })
    }),
  resendInvite: (tenantId: string, userId: string) =>
    req<void>(`/tenants/${tenantId}/users/${userId}/invite`, { method: 'POST' }),
  getRoutes: (slug: string) =>
    req<import('./types').RoutingConfig>(`/tenants/${slug}/routes`),
  replaceRoutes: (slug: string, body: import('./types').RoutingConfig) =>
    req<import('./types').RoutingConfig>(`/tenants/${slug}/routes`, {
      method: 'PUT', body: JSON.stringify(body)
    }),
};
