const base = '/api/v1';

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
};
