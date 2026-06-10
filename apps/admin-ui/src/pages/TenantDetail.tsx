import { useEffect, useMemo, useState } from 'react';
import { useParams, Link, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useMeContext, usePermission } from '@mcpmesh/auth-lib-react';
import { api } from '../api/client';
import RoutesTab from '../features/routes/RoutesTab';
import IdentityProvidersTab from '../features/idp/IdentityProvidersTab';
import BrandingTab from '../features/branding/BrandingTab';
import EmailTab from '../features/email/EmailTab';
import PermissionsTab from '../features/roles/PermissionsTab';
import RolesTab from '../features/roles/RolesTab';
import DataServicesTab from '../features/data-services/DataServicesTab';
import UserRolesPopover from '../features/roles/UserRolesPopover';
import { useRolesQuery } from '../features/roles/useRolesQuery';
import { useUserRealmRolesQueries } from '../features/roles/useUserRealmRolesQueries';
import ConfirmDialog from '../components/ConfirmDialog';
import { useToast } from '../components/Toast';

type TabKey = 'overview' | 'apps' | 'routes' | 'identity-providers' | 'branding' | 'email' | 'permissions' | 'roles' | 'data-services' | 'users' | 'audit';

const TAB_KEYS: readonly TabKey[] = [
  'overview', 'apps', 'routes', 'identity-providers', 'branding', 'email',
  'permissions', 'roles', 'data-services', 'users', 'audit',
];

function isTabKey(v: string | null): v is TabKey {
  return v !== null && (TAB_KEYS as readonly string[]).includes(v);
}

export default function TenantDetail() {
  const { id } = useParams<{ id: string }>();
  // Per-tab permission checks. Each tab is independently gated on an
  // atomic perm from PlatformPermissions; the backend enforces the same
  // perms via @PreAuthorize so the UI is mirroring authoritative state.
  const canViewTenant       = usePermission('TENANT_VIEW');
  const canEditApps         = usePermission('APPS_EDIT');
  const canEditRoutes       = usePermission('ROUTES_EDIT');
  const canEditIdp          = usePermission('IDP_EDIT');
  const canEditBranding     = usePermission('BRANDING_EDIT');
  const canEditPermissions  = usePermission('PERMISSIONS_EDIT');
  const canEditRoles        = usePermission('ROLES_EDIT');
  const canListUsers        = usePermission('USER_LIST');
  const canViewAudit        = usePermission('AUDIT_VIEW');

  // Active tab lives in a ?tab= search param (deep-linkable, refresh-safe,
  // and immune to state loss from the /me focus-refetch — see snap-back
  // guard below). Absent/unknown values default to 'overview'.
  const [searchParams, setSearchParams] = useSearchParams();
  const rawTab = searchParams.get('tab');
  const tab: TabKey = isTabKey(rawTab) ? rawTab : 'overview';
  const setTab = (next: TabKey) => {
    setSearchParams(prev => {
      const p = new URLSearchParams(prev);
      if (next === 'overview') p.delete('tab'); else p.set('tab', next);
      return p;
    }, { replace: true });
  };
  // isFetching is true for ANY in-flight /me request (including the
  // refetch-on-window-focus the auth lib does); usePermission default-DENIES
  // while it's true, so visibleTabs is transiently [] — not a real demotion.
  const { isFetching: meFetching } = useMeContext();
  const toast = useToast();
  const tenant = useQuery({ queryKey: ['tenant', id], queryFn: () => api.getTenant(id!), enabled: !!id });

  // Build the visible-tab list per-perm. Overview is the landing page and
  // is shown whenever the caller has access to ANY other tab; this keeps
  // tenant-user-manager (which holds USER_LIST/AUDIT_VIEW but not
  // TENANT_VIEW) seeing Overview as today.
  const visibleTabs: readonly TabKey[] = useMemo(() => {
    const t: TabKey[] = [];
    if (canEditApps)         t.push('apps');
    if (canEditRoutes)       t.push('routes');
    if (canEditIdp)          t.push('identity-providers');
    if (canEditBranding)     t.push('branding');
    // Email tab uses TENANT_EDIT for writes, TENANT_VIEW for reads. Visible
    // whenever the caller can see the tenant — the form is read-only without
    // TENANT_EDIT (gated inside the tab).
    if (canViewTenant)       t.push('email');
    if (canEditPermissions)  t.push('permissions');
    if (canEditRoles)        t.push('roles');
    // Data Services tab is read-on-VIEW, mutate-on-EDIT (the tab itself
    // gates the provision/deprovision buttons on TENANT_EDIT). Showing on
    // VIEW means tenant-user-managers can see the connection coordinates
    // (but not the password) without being able to mutate.
    if (canViewTenant)       t.push('data-services');
    if (canListUsers)        t.push('users');
    if (canViewAudit)        t.push('audit');
    return t.length > 0 ? ['overview', ...t] : [];
  }, [canViewTenant, canEditApps, canEditRoutes, canEditIdp, canEditBranding, canEditPermissions, canEditRoles, canListUsers, canViewAudit]);

  // If the selected tab is no longer in the visible set (e.g. /me resolved
  // late and demoted the caller's tier), snap to the first visible one.
  // Skip while /me is merely refetching (perms unknown, not demoted) and
  // while visibleTabs is empty for the same reason.
  useEffect(() => {
    if (meFetching) return;
    if (visibleTabs.length === 0) return;
    if (!visibleTabs.includes(tab)) setTab(visibleTabs[0] ?? 'overview');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, visibleTabs, meFetching]);

  if (tenant.isLoading) return <div>Loading…</div>;
  if (tenant.isError) return <div className="text-red-700">{String(tenant.error)}</div>;
  if (!tenant.data) return null;

  const t = tenant.data;
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Link to="/tenants" className="text-slate-500 hover:text-slate-900">← Tenants</Link>
        <h1 className="text-2xl font-semibold">{t.displayName}</h1>
        <code className="text-xs text-slate-500">{t.slug}</code>
        <div className="ml-auto">
          <button
            onClick={async () => {
              try { await api.downloadOnboardingBundle(t.id); }
              catch (e) { toast.error('Download failed: ' + (e instanceof Error ? e.message : String(e))); }
            }}
            className="bg-white border px-3 py-1.5 rounded text-sm hover:bg-slate-50"
          >
            Download bundle
          </button>
        </div>
      </div>
      <div className="flex gap-4 border-b">
        {visibleTabs.map(k => (
          <button key={k} onClick={() => setTab(k)}
                  className={'pb-2 px-1 text-sm ' + (tab === k ? 'border-b-2 border-slate-900 text-slate-900' : 'text-slate-500 hover:text-slate-900')}>
            {tabLabel(k)}
          </button>
        ))}
      </div>
      {tab === 'overview' && <OverviewTab tenant={t} />}
      {tab === 'apps' && <AppsTab tenantId={t.id} />}
      {tab === 'routes' && <RoutesTab slug={t.slug} />}
      {tab === 'identity-providers' && <IdentityProvidersTab slug={t.slug} tenantId={t.id} />}
      {tab === 'branding' && <BrandingTab slug={t.slug} />}
      {tab === 'email' && <EmailTab tenantId={t.id} slug={t.slug} />}
      {tab === 'permissions' && <PermissionsTab id={t.id} slug={t.slug} />}
      {tab === 'roles' && <RolesTab slug={t.slug} />}
      {tab === 'data-services' && <DataServicesTab tenantId={t.id} slug={t.slug} />}
      {tab === 'users' && <UsersTab tenantId={t.id} slug={t.slug} />}
      {tab === 'audit' && <AuditTab tenantId={t.id} />}
    </div>
  );
}

function tabLabel(k: string): string {
  if (k === 'identity-providers') return 'Identity Providers';
  if (k === 'data-services') return 'Data Services';
  return k.charAt(0).toUpperCase() + k.slice(1);
}

function OverviewTab({ tenant }: { tenant: import('../api/types').Tenant }) {
  return (
    <dl className="bg-white border rounded p-4 space-y-2 text-sm">
      <Row k="Status" v={<span className="font-mono">{tenant.status}</span>} />
      <Row k="Realm" v={<span className="font-mono">{tenant.realmName ?? '—'}</span>} />
      <Row k="ID" v={<span className="font-mono text-xs">{tenant.id}</span>} />
      <Row k="Created" v={new Date(tenant.createdAt).toLocaleString() + ' by ' + tenant.createdBy} />
      <Row k="Hostnames" v={
        tenant.hostnames.length === 0 ? <span className="text-slate-400">none</span> :
        <ul>{tenant.hostnames.map(h => <li key={h.host} className="font-mono text-xs">{h.host} → {h.backend}</li>)}</ul>
      } />
    </dl>
  );
}

function Row({ k, v }: { k: string, v: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-2">
      <dt className="text-slate-500">{k}</dt>
      <dd>{v}</dd>
    </div>
  );
}

// SA permissions catalog. Kept in sync (manually) with TenantWizard's preset;
// the backend validates against the live usermanagement client-roles set, so
// anything unknown will be rejected server-side regardless of what we list.
const SA_PERMISSION_PRESET = ['USER_LIST', 'USER_INVITE', 'USER_DISABLE', 'AUDIT_VIEW', 'EMAIL_SEND', 'EMAIL_EDIT'];

function AppsTab({ tenantId }: { tenantId: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const canEditApps = usePermission('APPS_EDIT');
  const apps = useQuery({ queryKey: ['apps', tenantId], queryFn: () => api.listApps(tenantId) });
  const [showCreate, setShowCreate] = useState(false);
  const [slug, setSlug] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);
  const [saModalApp, setSaModalApp] = useState<import('../api/types').App | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<import('../api/types').App | null>(null);

  const create = useMutation({
    mutationFn: () => api.createApp(tenantId, { slug, displayName }),
    onSuccess: (app) => {
      qc.invalidateQueries({ queryKey: ['apps', tenantId] });
      setCreatedSecret(app.clientSecret);
      setSlug(''); setDisplayName('');
      setShowCreate(false);
    },
  });

  const del = useMutation({
    mutationFn: (appId: string) => api.deleteApp(tenantId, appId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['apps', tenantId] }),
  });

  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <h2 className="text-lg font-semibold">Apps</h2>
        <button onClick={() => setShowCreate(true)} className="bg-slate-900 text-white px-3 py-1 rounded text-sm hover:bg-slate-700">+ New app</button>
      </div>
      {createdSecret && (
        <div className="bg-amber-50 border border-amber-200 rounded p-3 text-sm">
          <div className="font-medium">New client secret (save this — shown only once)</div>
          <code className="font-mono text-xs break-all">{createdSecret}</code>
          <button onClick={() => setCreatedSecret(null)} className="ml-2 text-amber-700 hover:underline">dismiss</button>
        </div>
      )}
      {showCreate && (
        <form onSubmit={e => { e.preventDefault(); create.mutate(); }}
              className="bg-white border rounded p-3 grid grid-cols-2 gap-3">
          <input placeholder="slug" value={slug} onChange={e => setSlug(e.target.value)} className="border rounded px-2 py-1 text-sm font-mono" required />
          <input placeholder="display name" value={displayName} onChange={e => setDisplayName(e.target.value)} className="border rounded px-2 py-1 text-sm" required />
          <button type="submit" className="col-span-2 bg-slate-900 text-white px-3 py-1 rounded text-sm hover:bg-slate-700">Create</button>
        </form>
      )}
      <table className="w-full bg-white border rounded text-sm">
        <thead className="bg-slate-50 text-left">
          <tr>
            <th className="px-3 py-2">Slug</th>
            <th className="px-3 py-2">Display name</th>
            <th className="px-3 py-2">Created</th>
            <th className="px-3 py-2"></th>
          </tr>
        </thead>
        <tbody>
          {(apps.data ?? []).map(a => (
            <tr
              key={a.id}
              className={'border-t ' + (canEditApps ? 'cursor-pointer hover:bg-slate-50' : '')}
              onClick={canEditApps ? () => setSaModalApp(a) : undefined}
              title={canEditApps ? 'Click to edit service account permissions' : undefined}
            >
              <td className="px-3 py-2 font-mono">{a.slug}</td>
              <td className="px-3 py-2">{a.displayName}</td>
              <td className="px-3 py-2 text-slate-500">{new Date(a.createdAt).toLocaleDateString()}</td>
              <td className="px-3 py-2 text-right">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setDeleteTarget(a);
                  }}
                  className="text-red-700 hover:underline text-xs"
                >Delete</button>
              </td>
            </tr>
          ))}
          {(apps.data ?? []).length === 0 && <tr><td colSpan={4} className="px-3 py-6 text-center text-slate-500">No apps yet</td></tr>}
        </tbody>
      </table>

      {saModalApp && (
        <ServiceAccountPermissionsModal
          tenantId={tenantId}
          app={saModalApp}
          onClose={() => setSaModalApp(null)}
        />
      )}

      <ConfirmDialog
        isOpen={!!deleteTarget}
        title={`Delete app ${deleteTarget?.slug ?? ''}?`}
        description="This removes the app's Keycloak client. Anything authenticating as this app will stop working."
        confirmLabel="Delete"
        danger
        isLoading={del.isPending}
        onCancel={() => setDeleteTarget(null)}
        onConfirm={() => {
          if (!deleteTarget) return;
          const appSlug = deleteTarget.slug;
          del.mutate(deleteTarget.id, {
            onSuccess: () => {
              toast.success(`App ${appSlug} deleted`);
              setDeleteTarget(null);
            },
            onError: (err) => {
              toast.error(`Delete failed: ${err instanceof Error ? err.message : String(err)}`);
              setDeleteTarget(null);
            },
          });
        }}
      />
    </div>
  );
}

/**
 * Modal for editing an app's service-account permissions (KC client roles on
 * the `usermanagement` client). Fetches the current set on open, lets the
 * operator toggle the SA_PERMISSION_PRESET catalog, and PUTs the new set on
 * Save. Apps without a service account (e.g. SPA_PKCE) render a short notice
 * instead of checkboxes.
 *
 * Detection: the GET endpoint returns an empty list for two distinct cases —
 * (a) the app's client has no SA at all (SPA_PKCE), or (b) the SA exists but
 * has zero perms granted. We can't disambiguate from the wire response alone,
 * so we just show checkboxes-with-empty-state in both cases; the backend will
 * reject the Save with a clear error if the SA truly doesn't exist.
 */
function ServiceAccountPermissionsModal({
  tenantId, app, onClose,
}: {
  tenantId: string;
  app: import('../api/types').App;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const current = useQuery({
    queryKey: ['app-sa-perms', tenantId, app.id],
    queryFn: () => api.getServiceAccountPermissions(tenantId, app.id),
  });
  const [selected, setSelected] = useState<Set<string> | null>(null);

  // Initialize the checkbox state once the GET resolves.
  useEffect(() => {
    if (current.data && selected === null) {
      setSelected(new Set(current.data.permissions));
    }
  }, [current.data, selected]);

  const save = useMutation({
    mutationFn: () =>
      api.updateServiceAccountPermissions(tenantId, app.id, Array.from(selected ?? new Set())),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['apps', tenantId] });
      qc.invalidateQueries({ queryKey: ['app-sa-perms', tenantId, app.id] });
      onClose();
    },
  });

  const toggle = (p: string) => {
    setSelected(prev => {
      const next = new Set(prev ?? new Set<string>());
      if (next.has(p)) next.delete(p); else next.add(p);
      return next;
    });
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/30 flex items-start justify-center p-6 overflow-y-auto"
         onClick={onClose}>
      <div className="bg-white rounded shadow-lg w-full max-w-lg p-5 space-y-3 mt-12"
           onClick={(e) => e.stopPropagation()}>
        <div>
          <h3 className="text-lg font-semibold">Service account permissions</h3>
          <div className="text-sm text-slate-500">
            <span>{app.displayName}</span>
            <span className="ml-2 font-mono text-xs">({app.slug})</span>
          </div>
        </div>
        <div className="text-xs text-slate-500">
          Granted to this app's service account on the usermanagement client.
          Tenant-app backends using client_credentials authenticate with these
          permissions.
        </div>

        {current.isLoading && <div className="text-sm text-slate-500">Loading…</div>}
        {current.isError && (
          <div className="text-red-700 text-sm">{String(current.error)}</div>
        )}

        {current.data && selected !== null && (
          <div className="space-y-1">
            {SA_PERMISSION_PRESET.map(p => (
              <label key={p} className="flex items-center gap-2 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  checked={selected.has(p)}
                  onChange={() => toggle(p)}
                />
                <span className="font-mono text-xs">{p}</span>
              </label>
            ))}
          </div>
        )}

        {save.isError && (
          <div className="text-red-700 text-xs">{String(save.error)}</div>
        )}

        <div className="flex gap-2 justify-end pt-2 border-t">
          <button
            type="button"
            onClick={onClose}
            className="text-sm text-slate-600 hover:text-slate-900 px-3 py-1"
          >Cancel</button>
          <button
            type="button"
            onClick={() => save.mutate()}
            disabled={save.isPending || current.isLoading || selected === null}
            className="bg-slate-900 text-white px-3 py-1 rounded text-sm hover:bg-slate-700 disabled:opacity-50"
          >{save.isPending ? 'Saving…' : 'Save'}</button>
        </div>
      </div>
    </div>
  );
}

function AuditTab({ tenantId }: { tenantId: string }) {
  const audit = useQuery({ queryKey: ['audit', tenantId], queryFn: () => api.tenantAudit(tenantId, 0, 50) });
  if (audit.isLoading) return <div>Loading…</div>;
  if (audit.isError) return <div className="text-red-700">{String(audit.error)}</div>;
  return (
    <ul className="space-y-2">
      {(audit.data?.items ?? []).map(e => (
        <li key={e.id} className="bg-white border rounded p-3 text-sm">
          <div className="flex justify-between">
            <div>
              <span className={'font-mono ' + (e.result === 'SUCCESS' ? 'text-emerald-700' : 'text-red-700')}>{e.result}</span>
              <span className="ml-2 font-semibold">{e.action}</span>
            </div>
            <div className="text-slate-500">{new Date(e.occurredAt).toLocaleString()}</div>
          </div>
          {Object.keys(e.details).length > 0 && (
            <pre className="text-xs mt-1 text-slate-600 overflow-x-auto">{JSON.stringify(e.details, null, 2)}</pre>
          )}
        </li>
      ))}
      {(audit.data?.items ?? []).length === 0 && <li className="text-slate-500">No audit entries</li>}
    </ul>
  );
}

function UsersTab({ tenantId, slug }: { tenantId: string; slug: string }) {
  const qc = useQueryClient();
  // Per-action atomic perm gates. tenant-user-manager holds the user-mgmt
  // bundle (USER_INVITE / USER_DISABLE / USER_REALM_ROLE_ASSIGN) but NOT
  // USER_SYSTEM_ROLE_ASSIGN — that one is tenant-admin-only and gates the
  // System Roles section in the role popover (privilege-escalation guard,
  // also enforced server-side via @PreAuthorize).
  const canInvite = usePermission('USER_INVITE');
  const canDisable = usePermission('USER_DISABLE');
  const canAssignRealmRoles = usePermission('USER_REALM_ROLE_ASSIGN');
  // "canManage" here is whether any per-row management affordance should
  // render (invite button, role-popover open, disable). Any of the
  // user-mgmt perms is sufficient.
  const canManage = canInvite || canDisable || canAssignRealmRoles;
  const toast = useToast();
  const [search, setSearch] = useState('');
  const [showInvite, setShowInvite] = useState(false);
  const [popoverUser, setPopoverUser] = useState<{ id: string; username: string } | null>(null);
  const [disableTarget, setDisableTarget] = useState<{ id: string; username: string } | null>(null);

  const users = useQuery({
    queryKey: ['users', tenantId, search],
    queryFn: () => api.listUsers(tenantId, search || undefined, 0, 200),
  });

  const roles = useRolesQuery(slug);

  // N+1 fetch realmRoles per user so the table can render composite-role badges.
  // The list endpoint only returns system client-roles; the slug-keyed user
  // endpoint returns both. Bounded by max=200 above.
  const userIds = (users.data?.items ?? []).map(u => u.id);
  const realmRolesByUser = useUserRealmRolesQueries(slug, userIds);

  const disable = useMutation({
    mutationFn: (userId: string) => api.disableUser(tenantId, userId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users', tenantId] }),
  });

  const resend = useMutation({
    mutationFn: (userId: string) => api.resendInvite(tenantId, userId),
    onSuccess: () => toast.success('Invite re-sent'),
    onError: (err) => toast.error(`Resend failed: ${err instanceof Error ? err.message : String(err)}`),
  });

  // Operator override for users stuck on KC's verify-email gate (#90).
  // Backend gates this on USER_INVITE — same affordance tier as resend.
  const verifyEmail = useMutation({
    mutationFn: (userId: string) => api.verifyUserEmail(tenantId, userId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users', tenantId] });
      toast.success('Email marked verified');
    },
    onError: (err) => toast.error(`Mark verified failed: ${err instanceof Error ? err.message : String(err)}`),
  });

  // Build a roleName -> description map for tooltips on the row badges.
  const roleDescByName: Record<string, string> = {};
  for (const r of roles.data ?? []) {
    if (r.description) roleDescByName[r.name] = r.description;
  }

  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <h2 className="text-lg font-semibold">Users</h2>
        <div className="flex gap-2">
          <input value={search} onChange={e => setSearch(e.target.value)}
                 placeholder="Search by name or email"
                 className="border rounded px-2 py-1 text-sm" />
          {canInvite && (
            <button onClick={() => setShowInvite(true)}
                    className="bg-slate-900 text-white px-3 py-1 rounded text-sm hover:bg-slate-700">
              + Invite user
            </button>
          )}
        </div>
      </div>

      {showInvite && (
        <InviteUserForm
          tenantId={tenantId}
          slug={slug}
          availableRoles={roles.data ?? []}
          onClose={() => setShowInvite(false)}
        />
      )}

      {users.isLoading && <div>Loading…</div>}
      {users.isError && <div className="text-red-700">{String(users.error)}</div>}
      {users.data && (
        <table className="w-full bg-white border rounded text-sm">
          <thead className="bg-slate-50 text-left">
            <tr>
              <th className="px-3 py-2">User</th>
              <th className="px-3 py-2">Email verified</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Roles</th>
              <th className="px-3 py-2 w-1"></th>
            </tr>
          </thead>
          <tbody>
            {users.data.items.map(u => {
              const realmRoles = realmRolesByUser[u.id] ?? [];
              return (
                <tr key={u.id} className="border-t align-top">
                  <td className="px-3 py-2">
                    <div className="font-mono">{u.username}</div>
                    {(u.firstName || u.lastName) && (
                      <div className="text-xs text-slate-500">{[u.firstName, u.lastName].filter(Boolean).join(' ')}</div>
                    )}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    {u.emailVerified ? <span className="text-emerald-700">✓ verified</span>
                                     : <span className="text-amber-700">⚠ pending</span>}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    {u.enabled ? <span className="text-emerald-700">enabled</span>
                               : <span className="text-slate-500">disabled</span>}
                  </td>
                  <td className="px-3 py-2">
                    <RoleBadges
                      systemRoles={u.roles}
                      realmRoles={realmRoles}
                      descByName={roleDescByName}
                      onClick={canManage ? () => setPopoverUser({ id: u.id, username: u.username }) : undefined}
                    />
                  </td>
                  <td className="px-3 py-2 text-right text-xs whitespace-nowrap">
                    {!u.emailVerified && (
                      <button onClick={() => resend.mutate(u.id)} className="text-blue-700 hover:underline">
                        resend invite
                      </button>
                    )}
                    {!u.emailVerified && (
                      <button
                        onClick={() => verifyEmail.mutate(u.id)}
                        disabled={verifyEmail.isPending}
                        className="text-emerald-700 hover:underline ml-2 disabled:opacity-50"
                      >mark verified</button>
                    )}
                    {' '}
                    {canDisable && u.enabled && (
                      <button
                        onClick={() => setDisableTarget({ id: u.id, username: u.username })}
                        className="text-red-700 hover:underline ml-2"
                      >disable</button>
                    )}
                  </td>
                </tr>
              );
            })}
            {users.data.items.length === 0 && (
              <tr><td colSpan={5} className="px-3 py-6 text-center text-slate-500">No users.</td></tr>
            )}
          </tbody>
        </table>
      )}

      {popoverUser && (
        <UserRolesPopover
          slug={slug}
          tenantId={tenantId}
          userId={popoverUser.id}
          username={popoverUser.username}
          availableRoles={roles.data ?? []}
          onClose={() => setPopoverUser(null)}
        />
      )}

      <ConfirmDialog
        isOpen={!!disableTarget}
        title={`Disable ${disableTarget?.username ?? ''}?`}
        description="The user can no longer sign in. They can be re-enabled later from Keycloak."
        confirmLabel="Disable"
        isLoading={disable.isPending}
        onCancel={() => setDisableTarget(null)}
        onConfirm={() => {
          if (!disableTarget) return;
          const username = disableTarget.username;
          disable.mutate(disableTarget.id, {
            onSuccess: () => {
              toast.success(`User ${username} disabled`);
              setDisableTarget(null);
            },
            onError: (err) => {
              toast.error(`Disable failed: ${err instanceof Error ? err.message : String(err)}`);
              setDisableTarget(null);
            },
          });
        }}
      />
    </div>
  );
}

/**
 * Per-chip classname. Distinguishes:
 *   - tenant-admin           — outlined slate (full admin)
 *   - tenant-user-manager    — filled blue (user-management only; visually
 *                              lighter than tenant-admin so the difference
 *                              is obvious at a glance in the user table)
 *   - other system roles     — outlined slate (catch-all)
 *   - composite realm roles  — filled slate
 */
function chipClassFor(r: { name: string; system: boolean }): string {
  if (r.system && r.name === 'tenant-user-manager') {
    return 'bg-blue-100 text-blue-800 border border-blue-200 text-xs px-2 py-0.5 rounded';
  }
  if (r.system) {
    return 'border border-slate-300 text-slate-700 text-xs px-2 py-0.5 rounded';
  }
  return 'bg-slate-100 text-slate-700 text-xs px-2 py-0.5 rounded';
}

/**
 * Compact role chips for a user row. tenant-admin is shown as an outlined
 * system badge; tenant-user-manager as a filled blue badge to mark it as
 * a distinct lighter-weight tier; composite realm roles are shown as
 * filled badges. The user-viewer system role is the universal baseline
 * and is hidden from the UI (every user has it, so showing it would be
 * noise).
 */
function RoleBadges({
  systemRoles,
  realmRoles,
  descByName,
  onClick,
}: {
  systemRoles: string[];
  realmRoles: string[];
  descByName: Record<string, string>;
  onClick?: () => void;
}) {
  const MAX = 3;
  const visibleSystem = systemRoles.filter(r => r !== 'user-viewer');
  const all = [
    ...visibleSystem.map(r => ({ name: r, system: true })),
    ...realmRoles.map(r => ({ name: r, system: false })),
  ];
  const shown = all.slice(0, MAX);
  const extra = all.length - shown.length;

  const inner = (
    <div className="flex gap-1 flex-wrap">
      {shown.map(r => (
        <span
          key={(r.system ? 's:' : 'r:') + r.name}
          title={descByName[r.name] ?? (r.system ? 'system role' : r.name)}
          className={chipClassFor(r)}
        >
          {r.name}
        </span>
      ))}
      {extra > 0 && (
        <span className="text-xs text-slate-500 self-center">+{extra} more</span>
      )}
      {all.length === 0 && (
        <span className="text-xs text-slate-400 italic">—</span>
      )}
    </div>
  );

  if (!onClick) return inner;
  return (
    <button
      type="button"
      onClick={onClick}
      className="text-left hover:bg-slate-50 rounded px-1 py-0.5 -mx-1 -my-0.5"
      title="Click to edit roles"
    >
      {inner}
    </button>
  );
}

function InviteUserForm({
  tenantId,
  slug,
  availableRoles,
  onClose,
}: {
  tenantId: string;
  slug: string;
  availableRoles: import('../api/types').RoleDto[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  // Logged-in operator's display name, rendered in the invite email's
  // "X invited you" line. Falls back through the /me user fields; the
  // backend ignores it where not applicable.
  const { me } = useMeContext();
  const inviterName = (me?.user.name || me?.user.preferredUsername || me?.user.email || '').slice(0, 255);
  const [email, setEmail] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  // user-viewer is a universal baseline granted by the backend on every
  // user. The system-role toggles exposed in the invite dialog are the
  // optional tenant-admin elevation and its lighter peer tenant-user-manager
  // (Users + Audit tabs only). They are mutually exclusive — tenant-admin
  // is a superset.
  const [grantAdmin, setGrantAdmin] = useState(false);
  const [grantUserManager, setGrantUserManager] = useState(false);
  // Composite realm-roles (applied via a follow-up PUT after invite succeeds).
  const [composite, setComposite] = useState<Set<string>>(new Set());

  const toggleComposite = (n: string) => {
    setComposite(prev => {
      const next = new Set(prev);
      if (next.has(n)) next.delete(n); else next.add(n);
      return next;
    });
  };

  const invite = useMutation({
    mutationFn: async () => {
      // Always send user-viewer explicitly to keep the request honest, even
      // though the backend will enforce it regardless. tenant-admin wins
      // when both are somehow set; the UI also prevents that combo.
      const roles: string[] = ['user-viewer'];
      if (grantAdmin) roles.push('tenant-admin');
      else if (grantUserManager) roles.push('tenant-user-manager');
      const created = await api.createUser(tenantId, {
        email, firstName, lastName, roles,
        inviterName: inviterName || undefined,
      });
      if (composite.size > 0) {
        // Omit systemRoles: the invite POST already set the system roles
        // via the create payload; this follow-up only attaches composite
        // realm roles, leaving system assignments untouched.
        await api.updateUserRoles(slug, created.id, { realmRoles: Array.from(composite) });
      }
      return created;
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['users', tenantId] }); onClose(); },
  });

  return (
    <form onSubmit={e => { e.preventDefault(); invite.mutate(); }}
          className="bg-white border rounded p-3 space-y-2">
      <div className="grid grid-cols-2 gap-2">
        <input placeholder="email" type="email" value={email} onChange={e => setEmail(e.target.value)} required
               className="border rounded px-2 py-1 text-sm" />
        <div></div>
        <input placeholder="first name (optional)" value={firstName} onChange={e => setFirstName(e.target.value)}
               className="border rounded px-2 py-1 text-sm" />
        <input placeholder="last name (optional)" value={lastName} onChange={e => setLastName(e.target.value)}
               className="border rounded px-2 py-1 text-sm" />
      </div>

      <div className="space-y-1">
        <label className="flex items-center gap-2 text-sm cursor-pointer">
          <input
            type="checkbox"
            checked={grantAdmin}
            onChange={e => {
              setGrantAdmin(e.target.checked);
              if (e.target.checked) setGrantUserManager(false);
            }}
          />
          <span>Grant tenant-admin (full tenant management — Routes, IdP, Branding, Roles, Users)</span>
        </label>
        <label className="flex items-center gap-2 text-sm cursor-pointer">
          <input
            type="checkbox"
            checked={grantUserManager}
            onChange={e => {
              setGrantUserManager(e.target.checked);
              if (e.target.checked) setGrantAdmin(false);
            }}
          />
          <span>Grant tenant-user-manager (lighter alternative — Users + Audit only)</span>
        </label>
        <div className="text-xs text-slate-500 mt-0.5 ml-6">
          All users automatically get baseline view access (user-viewer). Pick at most one elevation.
        </div>
      </div>

      {availableRoles.length > 0 && (
        <div>
          <div className="text-xs font-medium text-slate-600 mb-1">Custom roles (optional)</div>
          <div className="flex gap-2 flex-wrap">
            {availableRoles.map(r => {
              const on = composite.has(r.name);
              return (
                <button
                  type="button"
                  key={r.name}
                  onClick={() => toggleComposite(r.name)}
                  title={r.description ?? r.name}
                  className={
                    'text-xs px-2 py-0.5 rounded border ' +
                    (on
                      ? 'bg-slate-900 text-white border-slate-900'
                      : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50')
                  }
                >
                  {r.name}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {invite.isError && <div className="text-red-700 text-xs">{String(invite.error)}</div>}
      <div className="flex gap-2">
        <button type="submit" disabled={invite.isPending}
                className="bg-slate-900 text-white px-3 py-1 rounded text-sm hover:bg-slate-700 disabled:opacity-50">
          {invite.isPending ? 'Inviting…' : 'Send invite'}
        </button>
        <button type="button" onClick={onClose} className="text-sm text-slate-600 hover:text-slate-900">Cancel</button>
      </div>
    </form>
  );
}
