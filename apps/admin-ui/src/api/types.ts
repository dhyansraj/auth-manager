export type TenantStatus = 'PENDING' | 'ACTIVE' | 'SUSPENDED' | 'FAILED' | 'DELETED';

export interface HostnameAssignment { host: string; backend: string; }

export interface Tenant {
  id: string;
  slug: string;
  displayName: string;
  realmName: string | null;
  status: TenantStatus;
  settings: Record<string, unknown>;
  hostnames: HostnameAssignment[];
  createdAt: string;
  createdBy: string;
  updatedAt: string;
}

export interface App {
  id: string;
  tenantId: string;
  slug: string;
  displayName: string;
  clientId: string;
  clientSecret: string | null;
  createdAt: string;
}

export type AuditResult = 'SUCCESS' | 'FAILURE';

export interface AuditEvent {
  id: number;
  occurredAt: string;
  actor: string;
  actorKind: string;
  tenantId: string | null;
  action: string;
  targetKind: string | null;
  targetId: string | null;
  requestHash: string | null;
  result: AuditResult;
  details: Record<string, unknown>;
}

export interface PageResponse<T> {
  items: T[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
}
