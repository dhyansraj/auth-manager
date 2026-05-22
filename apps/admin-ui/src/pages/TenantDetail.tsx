import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useIsPlatformAdmin, useIsTenantAdmin } from '@mcpmesh/auth-lib-react';
import { api } from '../api/client';
import RoutesTab from '../features/routes/RoutesTab';
import IdentityProvidersTab from '../features/idp/IdentityProvidersTab';
import PermissionsTab from '../features/roles/PermissionsTab';
import RolesTab from '../features/roles/RolesTab';
import UserRolesPopover from '../features/roles/UserRolesPopover';
import { useRolesQuery } from '../features/roles/useRolesQuery';
import { useUserRealmRolesQueries } from '../features/roles/useUserRealmRolesQueries';

export default function TenantDetail() {
  const { id } = useParams<{ id: string }>();
  const [tab, setTab] = useState<'overview' | 'apps' | 'routes' | 'identity-providers' | 'permissions' | 'roles' | 'users' | 'audit'>('overview');
  const tenant = useQuery({ queryKey: ['tenant', id], queryFn: () => api.getTenant(id!), enabled: !!id });

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
      </div>
      <div className="flex gap-4 border-b">
        {(['overview', 'apps', 'routes', 'identity-providers', 'permissions', 'roles', 'users', 'audit'] as const).map(k => (
          <button key={k} onClick={() => setTab(k)}
                  className={'pb-2 px-1 text-sm ' + (tab === k ? 'border-b-2 border-slate-900 text-slate-900' : 'text-slate-500 hover:text-slate-900')}>
            {tabLabel(k)}
          </button>
        ))}
      </div>
      {tab === 'overview' && <OverviewTab tenant={t} />}
      {tab === 'apps' && <AppsTab tenantId={t.id} />}
      {tab === 'routes' && <RoutesTab slug={t.slug} />}
      {tab === 'identity-providers' && <IdentityProvidersTab slug={t.slug} />}
      {tab === 'permissions' && <PermissionsTab slug={t.slug} />}
      {tab === 'roles' && <RolesTab slug={t.slug} />}
      {tab === 'users' && <UsersTab tenantId={t.id} slug={t.slug} />}
      {tab === 'audit' && <AuditTab tenantId={t.id} />}
    </div>
  );
}

function tabLabel(k: string): string {
  if (k === 'identity-providers') return 'Identity Providers';
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

function AppsTab({ tenantId }: { tenantId: string }) {
  const qc = useQueryClient();
  const apps = useQuery({ queryKey: ['apps', tenantId], queryFn: () => api.listApps(tenantId) });
  const [showCreate, setShowCreate] = useState(false);
  const [slug, setSlug] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);

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
            <tr key={a.id} className="border-t">
              <td className="px-3 py-2 font-mono">{a.slug}</td>
              <td className="px-3 py-2">{a.displayName}</td>
              <td className="px-3 py-2 text-slate-500">{new Date(a.createdAt).toLocaleDateString()}</td>
              <td className="px-3 py-2 text-right">
                <button onClick={() => { if (confirm(`Delete app ${a.slug}?`)) del.mutate(a.id); }}
                        className="text-red-700 hover:underline text-xs">Delete</button>
              </td>
            </tr>
          ))}
          {(apps.data ?? []).length === 0 && <tr><td colSpan={4} className="px-3 py-6 text-center text-slate-500">No apps yet</td></tr>}
        </tbody>
      </table>
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
  const canManage = useIsTenantAdmin() || useIsPlatformAdmin();
  const [search, setSearch] = useState('');
  const [showInvite, setShowInvite] = useState(false);
  const [popoverUser, setPopoverUser] = useState<{ id: string; username: string } | null>(null);

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
          {canManage && (
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
                    {' '}
                    {canManage && u.enabled && (
                      <button
                        onClick={() => { if (confirm(`Disable ${u.username}?`)) disable.mutate(u.id); }}
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
    </div>
  );
}

/**
 * Compact role chips for a user row. tenant-admin is shown as an outlined
 * system badge; composite realm roles are shown as filled badges. The
 * user-viewer system role is the universal baseline and is hidden from the
 * UI (every user has it, so showing it would be noise).
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
          className={
            r.system
              ? 'border border-slate-300 text-slate-700 text-xs px-2 py-0.5 rounded'
              : 'bg-slate-100 text-slate-700 text-xs px-2 py-0.5 rounded'
          }
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
  const [email, setEmail] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  // user-viewer is a universal baseline granted by the backend on every
  // user. The only system-role toggle exposed in the invite dialog is the
  // optional tenant-admin elevation.
  const [grantAdmin, setGrantAdmin] = useState(false);
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
      // though the backend will enforce it regardless.
      const roles = grantAdmin ? ['user-viewer', 'tenant-admin'] : ['user-viewer'];
      const created = await api.createUser(tenantId, {
        email, firstName, lastName, roles,
      });
      if (composite.size > 0) {
        await api.updateUserRealmRoles(slug, created.id, Array.from(composite));
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

      <div>
        <label className="flex items-center gap-2 text-sm cursor-pointer">
          <input type="checkbox" checked={grantAdmin} onChange={e => setGrantAdmin(e.target.checked)} />
          <span>Grant tenant-admin (in addition to baseline view access)</span>
        </label>
        <div className="text-xs text-slate-500 mt-0.5 ml-6">
          All users automatically get baseline view access (user-viewer). Check this to also grant admin rights.
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
