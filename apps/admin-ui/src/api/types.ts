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

export type UserRole = 'tenant-admin' | 'tenant-user-manager' | 'user-viewer';

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
  /** True if auto-assigned to every new user via default-roles composite or
   * IdP Hardcoded Role mapper. The popover renders these as checked + disabled. */
  isDefault: boolean;
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

// ---------------------------------------------------------------------------
// Identity Providers (per-tenant social-login brokering)
// ---------------------------------------------------------------------------

/** Provider id string union — keep in lockstep with backend SUPPORTED_PROVIDERS. */
export type IdentityProviderId = 'google' | 'github';

/** Per-tenant view of a social-login identity provider. */
export interface IdentityProviderDto {
  id: IdentityProviderId;
  displayName: string;
  /** True iff an IdP instance exists on the tenant realm. */
  enabled: boolean;
  /** True iff platform creds for this provider are configured (env vars set). */
  available: boolean;
}

// ---------------------------------------------------------------------------
// Branding / Custom Themes (per-tenant ConfigMap-backed theme files)
// ---------------------------------------------------------------------------

/** Summary of the current theme stored for a tenant. */
export interface ThemeMeta {
  configured: boolean;
  fileCount: number;
  totalBytes: number;
  lastModified: string | null;
}

export type ThemeRolloutState = 'READY' | 'ROLLING_OUT' | 'FAILED';

export interface ThemeRolloutStatus {
  state: ThemeRolloutState;
  progress: number;
}

/** Structured validation error returned by POST /theme on a 400. */
export interface ThemeValidationError {
  code: string;
  path: string;
  message: string;
}
