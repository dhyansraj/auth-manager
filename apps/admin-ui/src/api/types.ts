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

export interface User {
  id: string;
  username: string;
  email: string;
  firstName: string | null;
  lastName: string | null;
  enabled: boolean | null;
  emailVerified: boolean | null;
  createdAt: string | null;
  /** System client-roles on the usermanagement client (e.g. tenant-admin, user-viewer). */
  roles: string[];
  /** Composite (custom) realm-role names. Only populated by the slug-keyed user endpoint. */
  realmRoles?: string[];
}

export interface UserListResponse {
  items: User[];
  first: number;
  max: number;
  totalItems: number;
}

export interface CreateUserPayload {
  email: string;
  firstName?: string;
  lastName?: string;
  roles?: string[];
  sendInvite?: boolean;
}

export type UserRole = 'tenant-admin' | 'user-viewer';

export type AuthMode = 'PUBLIC' | 'REQUIRED' | 'OPTIONAL';

export interface RoutingRule {
  path: string;
  authMode: AuthMode;
  target: string;
}

export interface RoutingConfig {
  rules: RoutingRule[];
  targets: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Custom Roles (composite roles + atomic permissions)
// ---------------------------------------------------------------------------

/** An atomic permission exposed by an app (a KC client-role on the app client). */
export interface PermissionDto {
  client: string;
  name: string;
  description?: string | null;
}

/** Reference to an atomic permission, used in role create/update payloads. */
export interface PermissionRef {
  client: string;
  name: string;
}

/** A composite role (KC realm role whose constituents are atomic permissions). */
export interface RoleDto {
  name: string;
  description: string | null;
  permissions: PermissionDto[];
  userCount: number;
  system: boolean;
}

export interface CreateRoleRequest {
  name: string;
  description?: string | null;
  permissions: PermissionRef[];
}

export interface UpdateRoleRequest {
  description?: string | null;
  permissions: PermissionRef[];
}

/** Atomic-replace request for a user's composite role assignments. */
export interface UpdateUserRolesRequest {
  roleNames: string[];
}
