/**
 * Response shape from the platform's /me endpoints.
 *
 * Both auth-manager's `GET /api/v1/me` (under auth.mcp-mesh.io/admin/api/v1/me)
 * and app1-backend's `GET /api/me` (under app1.mcp-mesh.io/api/me) return this
 * exact shape. The library is agnostic to which backend served it.
 */
export interface MeResponse {
  user: {
    id: string;
    email: string;
    preferredUsername: string;
    name?: string;
  };
  context: 'platform' | 'tenant';
  tenant?: {
    id: string;
    slug: string;
    displayName: string;
    realmName: string;
  };
  isPlatformAdmin: boolean;
  isTenantAdmin: boolean;
  permissions: string[];
}
