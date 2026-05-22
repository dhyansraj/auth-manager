import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { RoleDto } from '../../api/types';

interface Props {
  slug: string;
  tenantId: string;
  userId: string;
  username: string;
  /** Available composite roles in this tenant. */
  availableRoles: RoleDto[];
  onClose: () => void;
}

/**
 * Click-outside-to-close multi-select popover for editing a user's composite
 * realm roles. Fetches the user (slug-keyed) on open to seed the current
 * selection from `realmRoles`, PUTs the full desired set on Save.
 */
export default function UserRolesPopover({
  slug, tenantId, userId, username, availableRoles, onClose,
}: Props) {
  const qc = useQueryClient();

  const user = useQuery({
    queryKey: ['user-detail', slug, userId],
    queryFn: () => api.getUserBySlug(slug, userId),
  });

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [seeded, setSeeded] = useState(false);

  useEffect(() => {
    if (!seeded && user.data) {
      setSelected(new Set(user.data.realmRoles ?? []));
      setSeeded(true);
    }
  }, [user.data, seeded]);

  const save = useMutation({
    mutationFn: () => api.updateUserRealmRoles(slug, userId, Array.from(selected)),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users', tenantId] });
      qc.invalidateQueries({ queryKey: ['user-detail', slug, userId] });
      qc.invalidateQueries({ queryKey: ['roles', slug] });
      onClose();
    },
  });

  const toggle = (name: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
  };

  return (
    <div
      className="fixed inset-0 bg-slate-900/30 z-50 flex items-start justify-center pt-20 px-4"
      onClick={onClose}
    >
      <div
        onClick={e => e.stopPropagation()}
        className="bg-white border rounded shadow-lg w-full max-w-md max-h-[60vh] flex flex-col"
      >
        <div className="px-3 py-2 border-b flex justify-between items-center">
          <div className="text-sm font-semibold">Roles for <code className="font-mono">{username}</code></div>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-slate-900"
            aria-label="Close"
          >×</button>
        </div>

        <div className="px-3 py-2 overflow-y-auto flex-1">
          {user.isLoading && <div className="text-sm text-slate-500">Loading…</div>}
          {user.isError && (
            <div className="text-red-700 text-sm">{String(user.error)}</div>
          )}

          {availableRoles.length === 0 && user.data && (
            <div className="text-sm text-slate-500">
              No custom roles defined yet. Create one on the Roles tab.
            </div>
          )}

          {user.data && availableRoles.length > 0 && (
            <ul className="space-y-1">
              {availableRoles.map(r => (
                <li key={r.name}>
                  <label className="flex items-start gap-2 cursor-pointer text-sm py-1 px-1 hover:bg-slate-50 rounded">
                    <input
                      type="checkbox"
                      checked={selected.has(r.name)}
                      onChange={() => toggle(r.name)}
                      className="mt-0.5"
                    />
                    <div className="flex-1">
                      <div className="font-mono text-xs">{r.name}</div>
                      {r.description && (
                        <div className="text-xs text-slate-500">{r.description}</div>
                      )}
                    </div>
                  </label>
                </li>
              ))}
            </ul>
          )}

          {save.isError && (
            <div className="mt-2 bg-red-50 border border-red-200 rounded p-2 text-xs text-red-900">
              {String(save.error)}
            </div>
          )}
        </div>

        <div className="px-3 py-2 border-t flex justify-end gap-2">
          <button
            onClick={onClose}
            className="border px-3 py-1 rounded text-sm text-slate-700 hover:bg-slate-50"
          >Cancel</button>
          <button
            onClick={() => save.mutate()}
            disabled={save.isPending || !user.data}
            className="bg-slate-900 text-white px-3 py-1 rounded text-sm hover:bg-slate-700 disabled:opacity-50"
          >
            {save.isPending ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}
