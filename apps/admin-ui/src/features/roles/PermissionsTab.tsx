import { useMemo } from 'react';
import type { PermissionDto } from '../../api/types';
import { usePermissionsQuery } from './useRolesQuery';

interface Props {
  slug: string;
}

export default function PermissionsTab({ slug }: Props) {
  const query = usePermissionsQuery(slug);

  const grouped = useMemo(() => groupByClient(query.data ?? []), [query.data]);

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">Permissions</h2>
        <p className="text-xs text-slate-500 mt-1">
          Defined by your app's permission manifest. Add or change permissions by
          updating the manifest and redeploying.
        </p>
      </div>

      {query.isLoading && <div>Loading…</div>}
      {query.isError && <div className="text-red-700 text-sm">{String(query.error)}</div>}

      {query.data && grouped.length === 0 && (
        <div className="bg-white border rounded p-6 text-center text-slate-500 text-sm">
          No permissions found — apply a manifest to your app first.
        </div>
      )}

      {grouped.map(group => (
        <div key={group.client} className="bg-white border rounded shadow-sm">
          <div className="px-3 py-2 border-b bg-slate-50">
            <code className="text-sm font-mono text-slate-900">{group.client}</code>
            <span className="ml-2 text-xs text-slate-500">
              {group.permissions.length} {group.permissions.length === 1 ? 'permission' : 'permissions'}
            </span>
          </div>
          <table className="w-full text-sm">
            <tbody>
              {group.permissions.map(p => (
                <tr key={p.name} className="border-b last:border-b-0">
                  <td className="px-3 py-2 font-mono w-1/3 align-top">{p.name}</td>
                  <td className="px-3 py-2 text-slate-600 align-top">
                    {p.description || <span className="text-slate-400">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  );
}

interface PermissionGroup {
  client: string;
  permissions: PermissionDto[];
}

function groupByClient(perms: PermissionDto[]): PermissionGroup[] {
  const map = new Map<string, PermissionDto[]>();
  for (const p of perms) {
    const arr = map.get(p.client) ?? [];
    arr.push(p);
    map.set(p.client, arr);
  }
  return Array.from(map.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([client, permissions]) => ({ client, permissions }));
}
