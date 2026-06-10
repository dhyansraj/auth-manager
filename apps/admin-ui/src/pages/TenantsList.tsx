import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { usePermission } from '@mcpmesh/auth-lib-react';
import { api } from '../api/client';
import type { Tenant } from '../api/types';
import ConfirmDialog from '../components/ConfirmDialog';
import { useToast } from '../components/Toast';

export default function TenantsList() {
  const qc = useQueryClient();
  const toast = useToast();
  const { data, isLoading, isError, error } = useQuery({ queryKey: ['tenants'], queryFn: api.listTenants });
  const [confirmTarget, setConfirmTarget] = useState<Tenant | null>(null);
  // Tenant CRUD is platform-admin only. Gate the buttons on the explicit
  // atomic perms (mirrors the @PreAuthorize annotations on
  // TenantController). The backend list endpoint already filters by what
  // the caller is allowed to see, so TENANT_LIST_ALL doesn't need to gate
  // the page render itself.
  const canCreate = usePermission('TENANT_CREATE');
  const canDelete = usePermission('TENANT_DELETE');

  const del = useMutation({
    mutationFn: api.deleteTenant,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tenants'] }),
  });

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-semibold">Tenants</h1>
        {canCreate && (
          <Link to="/tenants/new" className="bg-slate-900 text-white px-3 py-1.5 rounded text-sm hover:bg-slate-700">
            + New tenant
          </Link>
        )}
      </div>
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
                  {canDelete && (
                    <button onClick={() => setConfirmTarget(t)}
                            className="text-red-700 hover:underline text-xs">Delete</button>
                  )}
                  {t.status !== 'ACTIVE' && (
                    <Link
                      to={`/tenants/new?resume=${t.id}`}
                      className="text-blue-700 hover:underline text-xs ml-3"
                    >
                      Resume
                    </Link>
                  )}
                </td>
              </tr>
            ))}
            {data.length === 0 && (
              <tr><td colSpan={6} className="px-3 py-6 text-center text-slate-500">No tenants. Create one.</td></tr>
            )}
          </tbody>
        </table>
      )}
      <ConfirmDialog
        isOpen={!!confirmTarget}
        title={`Delete tenant ${confirmTarget?.slug ?? ''}?`}
        description="This permanently removes the tenant's Keycloak realm and edge routing. Apps under this tenant will stop authenticating."
        confirmLabel="Delete"
        danger
        requireText={confirmTarget?.slug}
        isLoading={del.isPending}
        onCancel={() => setConfirmTarget(null)}
        onConfirm={() => {
          if (!confirmTarget) return;
          const slug = confirmTarget.slug;
          del.mutate(confirmTarget.id, {
            onSuccess: () => {
              toast.success(`Tenant ${slug} deleted`);
              setConfirmTarget(null);
            },
            onError: (err) => {
              toast.error(`Delete failed: ${err instanceof Error ? err.message : String(err)}`);
              setConfirmTarget(null);
            },
          });
        }}
      />
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
