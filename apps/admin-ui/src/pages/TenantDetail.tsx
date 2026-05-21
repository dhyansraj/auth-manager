import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import RoutesTab from '../features/routes/RoutesTab';

export default function TenantDetail() {
  const { id } = useParams<{ id: string }>();
  const [tab, setTab] = useState<'overview' | 'apps' | 'routes' | 'users' | 'audit'>('overview');
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
        {(['overview', 'apps', 'routes', 'users', 'audit'] as const).map(k => (
          <button key={k} onClick={() => setTab(k)}
                  className={'pb-2 px-1 text-sm ' + (tab === k ? 'border-b-2 border-slate-900 text-slate-900' : 'text-slate-500 hover:text-slate-900')}>
            {k.charAt(0).toUpperCase() + k.slice(1)}
          </button>
        ))}
      </div>
      {tab === 'overview' && <OverviewTab tenant={t} />}
      {tab === 'apps' && <AppsTab tenantId={t.id} />}
      {tab === 'routes' && <RoutesTab slug={t.slug} />}
      {tab === 'users' && <UsersTab tenantId={t.id} />}
      {tab === 'audit' && <AuditTab tenantId={t.id} />}
    </div>
  );
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

function UsersTab({ tenantId }: { tenantId: string }) {
  const qc = useQueryClient();
  const [search, setSearch] = useState('');
  const [showInvite, setShowInvite] = useState(false);

  const users = useQuery({
    queryKey: ['users', tenantId, search],
    queryFn: () => api.listUsers(tenantId, search || undefined, 0, 200),
  });

  const disable = useMutation({
    mutationFn: (userId: string) => api.disableUser(tenantId, userId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users', tenantId] }),
  });

  const resend = useMutation({
    mutationFn: (userId: string) => api.resendInvite(tenantId, userId),
  });

  const setRoles = useMutation({
    mutationFn: ({ userId, roles }: { userId: string; roles: string[] }) =>
      api.updateUserRoles(tenantId, userId, roles),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users', tenantId] }),
  });

  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <h2 className="text-lg font-semibold">Users</h2>
        <div className="flex gap-2">
          <input value={search} onChange={e => setSearch(e.target.value)}
                 placeholder="Search by name or email"
                 className="border rounded px-2 py-1 text-sm" />
          <button onClick={() => setShowInvite(true)}
                  className="bg-slate-900 text-white px-3 py-1 rounded text-sm hover:bg-slate-700">
            + Invite user
          </button>
        </div>
      </div>

      {showInvite && <InviteUserForm tenantId={tenantId} onClose={() => setShowInvite(false)} />}

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
            {users.data.items.map(u => (
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
                  <RoleSelector roles={u.roles}
                                onChange={roles => setRoles.mutate({ userId: u.id, roles })} />
                </td>
                <td className="px-3 py-2 text-right text-xs whitespace-nowrap">
                  {!u.emailVerified && (
                    <button onClick={() => resend.mutate(u.id)} className="text-blue-700 hover:underline">
                      resend invite
                    </button>
                  )}
                  {' '}
                  {u.enabled && (
                    <button
                      onClick={() => { if (confirm(`Disable ${u.username}?`)) disable.mutate(u.id); }}
                      className="text-red-700 hover:underline ml-2"
                    >disable</button>
                  )}
                </td>
              </tr>
            ))}
            {users.data.items.length === 0 && (
              <tr><td colSpan={5} className="px-3 py-6 text-center text-slate-500">No users.</td></tr>
            )}
          </tbody>
        </table>
      )}
    </div>
  );
}

function RoleSelector({ roles, onChange }: { roles: string[]; onChange: (roles: string[]) => void }) {
  const all = ['tenant-admin', 'user-viewer'] as const;
  const set = new Set(roles);
  const toggle = (r: string) => {
    const next = new Set(set);
    if (next.has(r)) next.delete(r); else next.add(r);
    if (next.size === 0) return;
    onChange(Array.from(next));
  };
  return (
    <div className="flex gap-1 flex-wrap">
      {all.map(r => (
        <button key={r} onClick={() => toggle(r)}
                className={'px-2 py-0.5 rounded text-xs ' +
                  (set.has(r) ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200')}>
          {r}
        </button>
      ))}
    </div>
  );
}

function InviteUserForm({ tenantId, onClose }: { tenantId: string; onClose: () => void }) {
  const qc = useQueryClient();
  const [email, setEmail] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [role, setRole] = useState<'tenant-admin' | 'user-viewer'>('user-viewer');

  const invite = useMutation({
    mutationFn: () => api.createUser(tenantId, { email, firstName, lastName, roles: [role] }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['users', tenantId] }); onClose(); },
  });

  return (
    <form onSubmit={e => { e.preventDefault(); invite.mutate(); }}
          className="bg-white border rounded p-3 space-y-2">
      <div className="grid grid-cols-2 gap-2">
        <input placeholder="email" type="email" value={email} onChange={e => setEmail(e.target.value)} required
               className="border rounded px-2 py-1 text-sm" />
        <select value={role} onChange={e => setRole(e.target.value as 'tenant-admin' | 'user-viewer')}
                className="border rounded px-2 py-1 text-sm">
          <option value="user-viewer">user-viewer</option>
          <option value="tenant-admin">tenant-admin</option>
        </select>
        <input placeholder="first name (optional)" value={firstName} onChange={e => setFirstName(e.target.value)}
               className="border rounded px-2 py-1 text-sm" />
        <input placeholder="last name (optional)" value={lastName} onChange={e => setLastName(e.target.value)}
               className="border rounded px-2 py-1 text-sm" />
      </div>
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
