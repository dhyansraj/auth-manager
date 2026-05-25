import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { usePermission } from '@mcpmesh/auth-lib-react';
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

/** System client-roles the admin can toggle on/off (user-viewer is the
 * baseline and never appears here -- it's enforced by the backend). */
const SYSTEM_ROLES = ['tenant-admin', 'tenant-user-manager'] as const;
type SystemRole = typeof SYSTEM_ROLES[number];

/**
 * Click-outside-to-close multi-select popover for editing a user's roles.
 * Two sections:
 *   1. Custom (composite) realm roles — checkboxes for the tenant's
 *      manifest roles (e.g. customer, inspector for safesound; Order
 *      Admin / Order Manager for app1).
 *   2. System roles — tenant-admin and tenant-user-manager checkboxes on
 *      the usermanagement client. Mutually exclusive in the UI
 *      (tenant-admin is a strict superset); backend doesn't enforce that.
 *
 * Save sends a single atomic PUT with both arrays (or just realmRoles
 * when the viewer can't manage system roles).
 */
export default function UserRolesPopover({
  slug, tenantId, userId, username, availableRoles, onClose,
}: Props) {
  const qc = useQueryClient();
  // Promoting a user to tenant-admin / tenant-user-manager is the
  // privileged path -- requires USER_SYSTEM_ROLE_ASSIGN, which is bundled
  // into tenant-admin ONLY (NOT tenant-user-manager). Tenant-user-manager
  // holders therefore can't promote others (privilege-escalation gate,
  // also enforced server-side via @PreAuthorize).
  const canManageSystemRoles = usePermission('USER_SYSTEM_ROLE_ASSIGN');

  const user = useQuery({
    queryKey: ['user-detail', slug, userId],
    queryFn: () => api.getUserBySlug(slug, userId),
  });

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [selectedSystem, setSelectedSystem] = useState<Set<SystemRole>>(new Set());
  const [seeded, setSeeded] = useState(false);

  useEffect(() => {
    if (!seeded && user.data) {
      setSelected(new Set(user.data.realmRoles ?? []));
      const sysFromServer = (user.data.roles ?? []).filter((r): r is SystemRole =>
        (SYSTEM_ROLES as readonly string[]).includes(r));
      setSelectedSystem(new Set(sysFromServer));
      setSeeded(true);
    }
  }, [user.data, seeded]);

  const save = useMutation({
    mutationFn: () => api.updateUserRoles(slug, userId, {
      realmRoles: Array.from(selected),
      // Only send systemRoles when the viewer is allowed to touch them.
      // Omitting the field tells the backend to leave them alone (and is
      // also what the server-side stricter gate expects -- without
      // systemRoles the lighter canManageUsersInTenant authority is enough).
      ...(canManageSystemRoles ? { systemRoles: Array.from(selectedSystem) } : {}),
    }),
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

  /**
   * Mutually-exclusive system-role toggle. tenant-admin is a strict
   * superset of tenant-user-manager so they should never coexist on a
   * single user; ticking one unticks the other. (Backend accepts both
   * being set — this is a UI hint only.)
   */
  const toggleSystem = (name: SystemRole) => {
    setSelectedSystem(prev => {
      const next = new Set<SystemRole>();
      if (prev.has(name)) {
        // toggling off
      } else {
        next.add(name);
      }
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

        <div className="px-3 py-2 overflow-y-auto flex-1 space-y-3">
          {user.isLoading && <div className="text-sm text-slate-500">Loading…</div>}
          {user.isError && (
            <div className="text-red-700 text-sm">{String(user.error)}</div>
          )}

          {user.data && (
            <section>
              <div className="text-xs font-medium text-slate-600 mb-1">Custom roles</div>
              {availableRoles.length === 0 ? (
                <div className="text-sm text-slate-500">
                  No custom roles defined yet. Create one on the Roles tab.
                </div>
              ) : (
                <ul className="space-y-1">
                  {availableRoles.map(r => {
                    const isDefault = r.isDefault;
                    const defaultTitle = 'Default role — auto-assigned to new signups '
                      + 'via IdP. Direct assignment is removable per user.';
                    return (
                      <li key={r.name}>
                        <label
                          className="flex items-start gap-2 text-sm py-1 px-1 rounded cursor-pointer hover:bg-slate-50"
                          title={isDefault ? defaultTitle : undefined}
                        >
                          <input
                            type="checkbox"
                            checked={selected.has(r.name)}
                            onChange={() => toggle(r.name)}
                            className="mt-0.5"
                          />
                          <div className="flex-1">
                            <div className="font-mono text-xs">
                              {r.name}
                              {isDefault && (
                                <span className="text-xs italic text-slate-500 ml-2 font-sans">
                                  default
                                </span>
                              )}
                            </div>
                            {r.description && (
                              <div className="text-xs text-slate-500">{r.description}</div>
                            )}
                          </div>
                        </label>
                      </li>
                    );
                  })}
                </ul>
              )}
            </section>
          )}

          {user.data && (
            <section>
              <div className="text-xs font-medium text-slate-600 mb-1">
                System roles
                {!canManageSystemRoles && (
                  <span className="ml-2 text-slate-400 font-normal italic">
                    (read-only — requires tenant-admin)
                  </span>
                )}
              </div>
              <ul className="space-y-1">
                <li>
                  <label className={`flex items-start gap-2 text-sm py-1 px-1 rounded ${
                    canManageSystemRoles ? 'cursor-pointer hover:bg-slate-50' : 'opacity-70'}`}>
                    <input
                      type="checkbox"
                      checked={selectedSystem.has('tenant-admin')}
                      onChange={() => toggleSystem('tenant-admin')}
                      disabled={!canManageSystemRoles}
                      className="mt-0.5"
                    />
                    <div className="flex-1">
                      <div className="font-mono text-xs">tenant-admin</div>
                      <div className="text-xs text-slate-500">
                        Full tenant management (Routes, IdP, Branding, Roles, Users)
                      </div>
                    </div>
                  </label>
                </li>
                <li>
                  <label className={`flex items-start gap-2 text-sm py-1 px-1 rounded ${
                    canManageSystemRoles ? 'cursor-pointer hover:bg-slate-50' : 'opacity-70'}`}>
                    <input
                      type="checkbox"
                      checked={selectedSystem.has('tenant-user-manager')}
                      onChange={() => toggleSystem('tenant-user-manager')}
                      disabled={!canManageSystemRoles}
                      className="mt-0.5"
                    />
                    <div className="flex-1">
                      <div className="font-mono text-xs">tenant-user-manager</div>
                      <div className="text-xs text-slate-500">
                        Lighter alternative — Users + Audit only
                      </div>
                    </div>
                  </label>
                </li>
              </ul>
              <div className="text-xs text-slate-500 mt-1 ml-1">
                tenant-admin and tenant-user-manager are mutually exclusive. Baseline
                user-viewer is granted automatically.
              </div>
            </section>
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
