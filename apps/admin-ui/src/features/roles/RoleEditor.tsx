import { useMemo, useState } from 'react';
import type { PermissionDto, RoleDto } from '../../api/types';
import { usePermissionsQuery, useCreateRoleMutation, useUpdateRoleMutation } from './useRolesQuery';

interface Props {
  slug: string;
  /** Existing role being edited, or null when creating a new one. */
  role: RoleDto | null;
  onClose: () => void;
}

const NAME_PATTERN = /^[A-Za-z0-9 _-]{1,50}$/;

function permKey(p: { client: string; name: string }) {
  return `${p.client}::${p.name}`;
}

export default function RoleEditor({ slug, role, onClose }: Props) {
  const isEdit = role !== null;
  const perms = usePermissionsQuery(slug);
  const create = useCreateRoleMutation(slug);
  const update = useUpdateRoleMutation(slug);

  const [name, setName] = useState(role?.name ?? '');
  const [description, setDescription] = useState(role?.description ?? '');
  const [selected, setSelected] = useState<Set<string>>(
    new Set((role?.permissions ?? []).map(permKey))
  );

  const grouped = useMemo(() => {
    const map = new Map<string, PermissionDto[]>();
    for (const p of perms.data ?? []) {
      const arr = map.get(p.client) ?? [];
      arr.push(p);
      map.set(p.client, arr);
    }
    return Array.from(map.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([client, list]) => ({ client, list }));
  }, [perms.data]);

  const nameValid = isEdit || NAME_PATTERN.test(name);
  const nameError =
    !isEdit && name.length > 0 && !nameValid
      ? 'Name must match [A-Za-z0-9 _-]{1,50}'
      : null;

  const toggle = (key: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  };

  const toggleAllForClient = (client: string, list: PermissionDto[]) => {
    const keys = list.map(permKey);
    const allOn = keys.every(k => selected.has(k));
    setSelected(prev => {
      const next = new Set(prev);
      if (allOn) keys.forEach(k => next.delete(k));
      else keys.forEach(k => next.add(k));
      return next;
    });
  };

  const onSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (!nameValid && !isEdit) return;

    const permissions = Array.from(selected).map(k => {
      const [client, n] = k.split('::');
      return { client, name: n };
    });

    if (isEdit) {
      update.mutate(
        { name: role!.name, body: { description: description || null, permissions } },
        { onSuccess: () => onClose() }
      );
    } else {
      create.mutate(
        { name, description: description || null, permissions },
        { onSuccess: () => onClose() }
      );
    }
  };

  const pending = create.isPending || update.isPending;
  const error = create.error || update.error;

  return (
    <div
      className="fixed inset-0 bg-slate-900/40 z-50 flex items-start justify-center pt-12 px-4"
      onClick={onClose}
    >
      <form
        onSubmit={onSave}
        onClick={e => e.stopPropagation()}
        className="bg-white border rounded shadow-lg w-full max-w-2xl max-h-[80vh] flex flex-col"
      >
        <div className="px-4 py-3 border-b flex justify-between items-center">
          <h3 className="font-semibold">{isEdit ? `Edit role: ${role!.name}` : 'New role'}</h3>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-500 hover:text-slate-900"
            aria-label="Close"
          >×</button>
        </div>

        <div className="px-4 py-3 space-y-3 overflow-y-auto">
          <div>
            <label className="block text-xs font-medium text-slate-600 mb-1">Name</label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              disabled={isEdit}
              placeholder="Order Manager"
              required
              className="w-full border rounded px-2 py-1 text-sm disabled:bg-slate-100 disabled:text-slate-500"
            />
            {nameError && <div className="text-red-700 text-xs mt-1">{nameError}</div>}
            {isEdit && (
              <div className="text-xs text-slate-500 mt-1">Role name cannot be changed.</div>
            )}
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-600 mb-1">Description</label>
            <input
              value={description ?? ''}
              onChange={e => setDescription(e.target.value)}
              placeholder="Optional description"
              className="w-full border rounded px-2 py-1 text-sm"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-600 mb-1">Permissions</label>
            {perms.isLoading && <div className="text-sm text-slate-500">Loading permissions…</div>}
            {perms.isError && (
              <div className="text-red-700 text-sm">{String(perms.error)}</div>
            )}
            {perms.data && grouped.length === 0 && (
              <div className="text-sm text-slate-500 bg-slate-50 border rounded p-3">
                No permissions defined yet. Apply a manifest to your app first.
              </div>
            )}
            {grouped.map(({ client, list }) => {
              const keys = list.map(permKey);
              const allOn = keys.every(k => selected.has(k));
              const someOn = !allOn && keys.some(k => selected.has(k));
              return (
                <div key={client} className="border rounded mb-2">
                  <div className="px-2 py-1 bg-slate-50 border-b flex items-center justify-between">
                    <code className="text-sm font-mono">{client}</code>
                    <button
                      type="button"
                      onClick={() => toggleAllForClient(client, list)}
                      className="text-xs text-blue-700 hover:underline"
                    >
                      {allOn ? 'clear all' : someOn ? 'select all' : 'select all'}
                    </button>
                  </div>
                  <ul className="py-1">
                    {list.map(p => {
                      const k = permKey(p);
                      const checked = selected.has(k);
                      return (
                        <li key={k} className="px-2 py-1 hover:bg-slate-50">
                          <label className="flex items-start gap-2 cursor-pointer text-sm">
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={() => toggle(k)}
                              className="mt-0.5"
                            />
                            <div className="flex-1">
                              <code className="font-mono text-xs">{p.name}</code>
                              {p.description && (
                                <div className="text-xs text-slate-500">{p.description}</div>
                              )}
                            </div>
                          </label>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              );
            })}
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 rounded p-2 text-xs text-red-900">
              {String(error)}
            </div>
          )}
        </div>

        <div className="px-4 py-3 border-t flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="border px-3 py-1 rounded text-sm text-slate-700 hover:bg-slate-50"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={pending || (!isEdit && (!name || !nameValid))}
            className="bg-slate-900 text-white px-3 py-1 rounded text-sm hover:bg-slate-700 disabled:opacity-50"
          >
            {pending ? 'Saving…' : 'Save'}
          </button>
        </div>
      </form>
    </div>
  );
}
