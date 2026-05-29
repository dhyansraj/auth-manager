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
  /**
   * Skip the platform's double-submit CSRF check on cookie-authed
   * mutations matching this rule. Use only for embedded third-party UIs
   * (Redis Commander, Grafana, ...) that have their own session model and
   * don't send the platform's X-CSRF-Token header. Optional; defaults to
   * false. Only meaningful when authMode is REQUIRED.
   */
  bypassCsrf?: boolean;
  /**
   * Single permission id (a KC client-role or realm-role name) that must
   * appear in the caller's JWT for the request to proceed. Verbatim string
   * match against resource_access.<client>.roles[] / realm_access.roles[].
   * Optional; null/undefined/empty means "no extra permission check".
   * Only enforced when authMode is REQUIRED.
   */
  requiredPermission?: string | null;
  /**
   * Prefix stripped from the request URI before forwarding upstream. Used
   * for embedded third-party apps mounted under a subpath whose internal
   * links assume root (e.g. Redis Commander at /ops/redis/* whose XHRs go
   * to /apiv2/...). Should normally be the rule's path minus the trailing
   * /*. Optional; null/undefined/empty means "forward path as-is".
   */
  stripPrefix?: string | null;
  /**
   * Max request body in MB. Default 25. Capped at 100 (Cloudflare tunnel
   * ceiling). Enforced before forwarding upstream by checking Content-Length
   * on POST/PUT/PATCH/DELETE; oversize requests get 413. Chunked uploads
   * (no Content-Length) fall through to the nginx 100MB backstop.
   */
  maxBodyMb?: number | null;
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

// ---------------------------------------------------------------------------
// Rich-login Branding (mcpmesh.flexible parent theme)
// ---------------------------------------------------------------------------

export type LayoutVariant = 'centered' | 'split-left' | 'split-right' | 'bleed';

export type SlotName =
  | 'marketingLeft'
  | 'marketingRight'
  | 'aboveForm'
  | 'belowForm'
  | 'footer';

/** Per-tenant layout variant + slot HTML map. Round-trips through PUT /branding. */
export interface BrandingConfig {
  layoutVariant: LayoutVariant;
  slots: Partial<Record<SlotName, string>>;
}

// ---------------------------------------------------------------------------
// Data Services / Managed Postgres (per-tenant database on shared CNPG)
// ---------------------------------------------------------------------------

/** Status returned by GET /tenants/{id}/data/postgres. NEVER includes password. */
export interface DatabaseStatus {
  tenantSlug: string;
  provisioned: boolean;
  host: string | null;
  port: number | null;
  database: string | null;
  username: string | null;
}

/**
 * Reveal-once payload from POST /tenants/{id}/data/postgres. The
 * password field is the ONLY time the password is exposed; the operator
 * must copy it elsewhere before dismissing the UI reveal.
 */
export interface DatabaseProvisionResult {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  jdbcUrl: string;
}

// ---------------------------------------------------------------------------
// Per-tenant email config + SendGrid domain auth
// ---------------------------------------------------------------------------

export type DomainAuthStatus = 'NOT_STARTED' | 'PENDING' | 'VALID' | 'FAILED';

/**
 * Per-tenant email view returned by GET /tenants/{id}/email.
 *
 * {@code fromAddress} is the resolved value KC actually sends with.
 * {@code fromAddressOverride} is the raw tenant column or null — null means
 * we're falling back to the platform default.
 */
export interface TenantEmailResponse {
  fromAddress: string;
  fromAddressOverride: string | null;
  fromDisplayName: string;
  fromDisplayNameOverride: string | null;
  replyToAddress: string | null;
  sendgridDomainId: number | null;
  sendgridDomainValid: boolean | null;
  domainAuthStatus: DomainAuthStatus;
}

export interface TenantEmailUpdateRequest {
  fromAddress: string | null;
  fromDisplayName: string | null;
  replyToAddress: string | null;
}

/** One SendGrid DNS CNAME with its CF-push state. */
export interface DomainAuthCname {
  host: string;
  target: string;
  pushed: boolean;
  pushError: string | null;
}

export interface DomainAuthResponse {
  domain: string | null;
  sendgridDomainId: number | null;
  valid: boolean | null;
  zoneInOurAccount: boolean;
  cnames: DomainAuthCname[];
}

// ---------------------------------------------------------------------------
// Per-tenant login methods (username/password toggle + IdP listing)
// ---------------------------------------------------------------------------

export interface LoginMethodStatus {
  passwordEnabled: boolean;
  enabledIdpAliases: string[];
}
