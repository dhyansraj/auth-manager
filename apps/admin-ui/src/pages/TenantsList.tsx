import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';

export default function TenantsList() {
  const qc = useQueryClient();
  const { data, isLoading, isError, error } = useQuery({ queryKey: ['tenants'], queryFn: api.listTenants });
  const [showCreate, setShowCreate] = useState(false);

  const del = useMutation({
    mutationFn: api.deleteTenant,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tenants'] }),
  });

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-semibold">Tenants</h1>
        <button onClick={() => setShowCreate(true)} className="bg-slate-900 text-white px-3 py-1.5 rounded text-sm hover:bg-slate-700">
          + New tenant
        </button>
      </div>
      {showCreate && <CreateTenantForm onClose={() => setShowCreate(false)} />}
      {isLoading && <div>Loading…</div>}
      {isError && <div className="text-red-700">Error: {String(error)}</div>}
      {data && (
        <table className="w-full bg-white border rounded text-sm">
          <thead className="bg-slate-50 text-left">
            <tr>
              <th className="px-3 py-2">Slug</th>
              <th className="px-3 py-2">Display Name</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Realm</th>
              <th className="px-3 py-2">Created</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {data.map(t => (
              <tr key={t.id} className="border-t">
                <td className="px-3 py-2 font-mono"><Link to={`/tenants/${t.id}`} className="text-blue-700 hover:underline">{t.slug}</Link></td>
                <td className="px-3 py-2">{t.displayName}</td>
                <td className="px-3 py-2"><StatusBadge status={t.status} /></td>
                <td className="px-3 py-2 font-mono text-xs">{t.realmName ?? '—'}</td>
                <td className="px-3 py-2 text-slate-500">{new Date(t.createdAt).toLocaleDateString()}</td>
                <td className="px-3 py-2 text-right">
                  <button onClick={() => { if (confirm(`Delete tenant ${t.slug}?`)) del.mutate(t.id); }}
                          className="text-red-700 hover:underline text-xs">Delete</button>
                </td>
              </tr>
            ))}
            {data.length === 0 && (
              <tr><td colSpan={6} className="px-3 py-6 text-center text-slate-500">No tenants. Create one.</td></tr>
            )}
          </tbody>
        </table>
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cls = status === 'ACTIVE' ? 'bg-emerald-100 text-emerald-800'
            : status === 'PENDING' ? 'bg-amber-100 text-amber-800'
            : status === 'FAILED' ? 'bg-red-100 text-red-800'
            : 'bg-slate-100 text-slate-700';
  return <span className={`px-2 py-0.5 rounded text-xs font-medium ${cls}`}>{status}</span>;
}

function CreateTenantForm({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [slug, setSlug] = useState('');
  const [displayName, setDisplayName] = useState('');
  const create = useMutation({
    mutationFn: api.createTenant,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['tenants'] }); onClose(); },
  });

  return (
    <form onSubmit={e => { e.preventDefault(); create.mutate({ slug, displayName }); }}
          className="bg-white border rounded p-4 space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <label className="block">
          <div className="text-xs text-slate-600 mb-1">Slug (dns-safe)</div>
          <input value={slug} onChange={e => setSlug(e.target.value)} pattern="[a-z0-9]([a-z0-9\-]*[a-z0-9])?" required
                 className="w-full border rounded px-2 py-1 font-mono text-sm" />
        </label>
        <label className="block">
          <div className="text-xs text-slate-600 mb-1">Display name</div>
          <input value={displayName} onChange={e => setDisplayName(e.target.value)} required
                 className="w-full border rounded px-2 py-1 text-sm" />
        </label>
      </div>
      {create.isError && <div className="text-red-700 text-xs">{String(create.error)}</div>}
      <div className="flex gap-2">
        <button type="submit" disabled={create.isPending}
                className="bg-slate-900 text-white px-3 py-1.5 rounded text-sm hover:bg-slate-700 disabled:opacity-50">
          {create.isPending ? 'Creating…' : 'Create'}
        </button>
        <button type="button" onClick={onClose} className="text-sm text-slate-600 hover:text-slate-900">Cancel</button>
      </div>
    </form>
  );
}
