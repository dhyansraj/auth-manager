import { useState } from 'react';
import { usePermission } from '@mcpmesh/auth-lib-react';
import type { RoleDto } from '../../api/types';
import { useRolesQuery, useDeleteRoleMutation } from './useRolesQuery';
import { ApiError } from '../../api/client';
import RoleEditor from './RoleEditor';
import ConfirmDialog from '../../components/ConfirmDialog';
import { useToast } from '../../components/Toast';

interface Props {
  slug: string;
}

interface DeleteConflict {
  role: string;
  userCount: number;
}

export default function RolesTab({ slug }: Props) {
  const canManage = usePermission('ROLES_EDIT');
  const roles = useRolesQuery(slug);
  const del = useDeleteRoleMutation(slug);

  const toast = useToast();
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<RoleDto | null>(null);
  const [conflict, setConflict] = useState<DeleteConflict | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<RoleDto | null>(null);

  const openNew = () => { setEditing(null); setEditorOpen(true); };
  const openEdit = (r: RoleDto) => { setEditing(r); setEditorOpen(true); };
  const close = () => setEditorOpen(false);

  const confirmDelete = (r: RoleDto) => {
    setConflict(null);
    del.mutate(r.name, {
      onSuccess: () => {
        toast.success(`Role '${r.name}' deleted`);
        setDeleteTarget(null);
      },
      onError: (err) => {
        setDeleteTarget(null);
        if (err instanceof ApiError && err.status === 409) {
          const body = err.body as { error?: string; role?: string; userCount?: number } | null;
          if (body && body.error === 'role_in_use') {
            setConflict({ role: body.role ?? r.name, userCount: body.userCount ?? 0 });
            return;
          }
        }
        toast.error(`Delete failed: ${err instanceof Error ? err.message : String(err)}`);
      },
    });
  };

  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <h2 className="text-lg font-semibold">Roles</h2>
        {canManage && (
          <button
            onClick={openNew}
            className="bg-slate-900 text-white px-3 py-1 rounded text-sm hover:bg-slate-700"
          >
            + New role
          </button>
        )}
      </div>

      {conflict && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900 flex justify-between items-start">
          <div>
            This role is assigned to {conflict.userCount} user{conflict.userCount === 1 ? '' : 's'}.
            Remove it from those users on the Users tab first, then delete.
          </div>
          <button onClick={() => setConflict(null)} className="text-red-700 hover:underline ml-2">
            dismiss
          </button>
        </div>
      )}

      {del.isError && !conflict && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
          {String(del.error)}
        </div>
      )}

      {roles.isLoading && <div>Loading…</div>}
      {roles.isError && <div className="text-red-700 text-sm">{String(roles.error)}</div>}

      {roles.data && (
        <table className="w-full bg-white border rounded text-sm shadow-sm">
          <thead className="bg-slate-50 text-left">
            <tr>
              <th className="px-3 py-2">Name</th>
              <th className="px-3 py-2">Description</th>
              <th className="px-3 py-2">Permissions</th>
              <th className="px-3 py-2">Users</th>
              <th className="px-3 py-2 w-1"></th>
            </tr>
          </thead>
          <tbody>
            {roles.data.map(r => (
              <tr key={r.name} className="border-t align-top">
                <td className="px-3 py-2 font-mono">{r.name}</td>
                <td className="px-3 py-2 text-slate-600">
                  {r.description || <span className="text-slate-400">—</span>}
                </td>
                <td className="px-3 py-2">
                  <div className="text-xs text-slate-500 mb-1">{r.permissions.length}</div>
                  <div className="flex gap-1 flex-wrap">
                    {r.permissions.slice(0, 4).map(p => (
                      <span
                        key={`${p.client}:${p.name}`}
                        title={p.description ?? `${p.client}:${p.name}`}
                        className="bg-slate-100 text-slate-700 text-xs px-2 py-0.5 rounded font-mono"
                      >
                        {p.client}:{p.name}
                      </span>
                    ))}
                    {r.permissions.length > 4 && (
                      <span className="text-xs text-slate-500">
                        +{r.permissions.length - 4} more
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-3 py-2 text-slate-600">{r.userCount}</td>
                <td className="px-3 py-2 text-right text-xs whitespace-nowrap">
                  {canManage && (
                    <>
                      <button
                        onClick={() => openEdit(r)}
                        className="text-blue-700 hover:underline"
                      >Edit</button>
                      {' '}
                      <button
                        onClick={() => setDeleteTarget(r)}
                        className="text-red-700 hover:underline ml-2"
                        aria-label={`Delete ${r.name}`}
                      >Delete</button>
                    </>
                  )}
                </td>
              </tr>
            ))}
            {roles.data.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-center text-slate-500">
                  No custom roles yet.{canManage && " Click '+ New role' to create one."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}

      {editorOpen && (
        <RoleEditor slug={slug} role={editing} onClose={close} />
      )}

      <ConfirmDialog
        isOpen={!!deleteTarget}
        title={`Delete role '${deleteTarget?.name ?? ''}'?`}
        description="Users assigned this role lose the permissions it grants."
        confirmLabel="Delete"
        danger
        isLoading={del.isPending}
        onCancel={() => setDeleteTarget(null)}
        onConfirm={() => { if (deleteTarget) confirmDelete(deleteTarget); }}
      />
    </div>
  );
}
