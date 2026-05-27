import type { AuthMode, RoutingRule } from '../../api/types';
import type { RuleError } from './validate';

interface Props {
  rules: RoutingRule[];
  targetKeys: string[];
  ruleErrors: RuleError[];
  readOnly: boolean;
  onChange: (rules: RoutingRule[]) => void;
}

const AUTH_MODES: AuthMode[] = ['PUBLIC', 'REQUIRED', 'OPTIONAL'];

export default function RulesTable({ rules, targetKeys, ruleErrors, readOnly, onChange }: Props) {
  const errFor = (i: number, field: 'path' | 'target') =>
    ruleErrors.find(e => e.index === i && e.field === field)?.message;

  const update = (i: number, patch: Partial<RoutingRule>) => {
    const next = rules.map((r, idx) => (idx === i ? { ...r, ...patch } : r));
    onChange(next);
  };

  const remove = (i: number) => {
    onChange(rules.filter((_, idx) => idx !== i));
  };

  const add = () => {
    const defaultTarget = targetKeys[0] ?? '';
    onChange([
      ...rules,
      { path: '', authMode: 'REQUIRED', target: defaultTarget, bypassCsrf: false, requiredPermission: '', stripPrefix: '' },
    ]);
  };

  return (
    <div className="space-y-2">
      <div className="flex justify-between items-center">
        <h2 className="text-lg font-semibold">Rules</h2>
        {!readOnly && (
          <button
            type="button"
            onClick={add}
            className="bg-slate-900 text-white px-3 py-1 rounded text-sm hover:bg-slate-700"
          >
            + Add rule
          </button>
        )}
      </div>
      {!readOnly && (
        <p className="text-xs text-slate-500">
          Rules are auto-sorted by specificity on save (exact paths first, then longest prefix, <code>/*</code> last).
        </p>
      )}
      <table className="w-full bg-white border rounded text-sm">
        <thead className="bg-slate-50 text-left">
          <tr>
            <th className="px-3 py-2 w-10">#</th>
            <th className="px-3 py-2">Path</th>
            <th className="px-3 py-2 w-32">Auth Mode</th>
            <th className="px-3 py-2 w-48">Target</th>
            <th
              className="px-3 py-2 w-44"
              title="Optional. If set, request requires this permission claim in the JWT (in addition to auth). Skip if no permission gating needed."
            >
              Required permission
              <span className="ml-1 text-slate-400 cursor-help">(?)</span>
            </th>
            <th
              className="px-3 py-2 w-44"
              title="Optional. Strips this prefix from the request URI before forwarding. For embedded apps that don't support a base-path config. Common: same as the rule path minus the trailing /*."
            >
              Strip prefix
              <span className="ml-1 text-slate-400 cursor-help">(?)</span>
            </th>
            <th
              className="px-3 py-2 w-28"
              title="Skip CSRF check on cookie-authed mutations. Use for third-party UIs (Redis Commander, Grafana) that don't send X-CSRF-Token. Only meaningful when Auth Mode is REQUIRED."
            >
              Bypass CSRF
              <span className="ml-1 text-slate-400 cursor-help">(?)</span>
            </th>
            <th className="px-3 py-2 w-16 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r, i) => {
            const pathErr = errFor(i, 'path');
            const targetErr = errFor(i, 'target');
            return (
              <tr key={i} className="border-t align-top">
                <td className="px-3 py-2 text-slate-500 font-mono">{i + 1}</td>
                <td className="px-3 py-2">
                  <input
                    type="text"
                    value={r.path}
                    placeholder="/api/*"
                    disabled={readOnly}
                    onChange={e => update(i, { path: e.target.value })}
                    className={
                      'w-full border rounded px-2 py-1 font-mono text-sm disabled:bg-slate-100 ' +
                      (pathErr ? 'border-red-400' : '')
                    }
                  />
                  {pathErr && <div className="text-xs text-red-700 mt-1">{pathErr}</div>}
                </td>
                <td className="px-3 py-2">
                  <select
                    value={r.authMode}
                    disabled={readOnly}
                    onChange={e => update(i, { authMode: e.target.value as AuthMode })}
                    className="w-full border rounded px-2 py-1 text-sm disabled:bg-slate-100"
                  >
                    {AUTH_MODES.map(m => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </select>
                </td>
                <td className="px-3 py-2">
                  <select
                    value={r.target}
                    disabled={readOnly || targetKeys.length === 0}
                    onChange={e => update(i, { target: e.target.value })}
                    className={
                      'w-full border rounded px-2 py-1 text-sm font-mono disabled:bg-slate-100 ' +
                      (targetErr ? 'border-red-400' : '')
                    }
                  >
                    {targetKeys.length === 0 && <option value="">— no targets —</option>}
                    {!targetKeys.includes(r.target) && r.target && (
                      <option value={r.target}>{r.target} (missing)</option>
                    )}
                    {!targetKeys.includes(r.target) && !r.target && (
                      <option value="">— select target —</option>
                    )}
                    {targetKeys.map(k => (
                      <option key={k} value={k}>{k}</option>
                    ))}
                  </select>
                  {targetErr && <div className="text-xs text-red-700 mt-1">{targetErr}</div>}
                </td>
                <td className="px-3 py-2">
                  <input
                    type="text"
                    value={r.requiredPermission ?? ''}
                    placeholder="e.g. OPS_ACCESS"
                    disabled={readOnly}
                    onChange={e => update(i, { requiredPermission: e.target.value })}
                    title="Optional. If set, request requires this permission claim in the JWT (in addition to auth). Skip if no permission gating needed."
                    className="w-full border rounded px-2 py-1 font-mono text-sm disabled:bg-slate-100"
                  />
                </td>
                <td className="px-3 py-2">
                  <input
                    type="text"
                    value={r.stripPrefix ?? ''}
                    placeholder="e.g. /ops/redis"
                    disabled={readOnly}
                    onChange={e => update(i, { stripPrefix: e.target.value })}
                    title="Optional. Strips this prefix from the request URI before forwarding. For embedded apps that don't support a base-path config. Common: same as the rule path minus the trailing /*."
                    className="w-full border rounded px-2 py-1 font-mono text-sm disabled:bg-slate-100"
                  />
                </td>
                <td className="px-3 py-2">
                  <input
                    type="checkbox"
                    checked={Boolean(r.bypassCsrf)}
                    disabled={readOnly}
                    onChange={e => update(i, { bypassCsrf: e.target.checked })}
                    title="Skip CSRF check on cookie-authed mutations. Use for third-party UIs that don't send X-CSRF-Token."
                    className="h-4 w-4 disabled:opacity-50"
                  />
                </td>
                <td className="px-3 py-2 text-right whitespace-nowrap">
                  {!readOnly && (
                    <button
                      type="button"
                      onClick={() => remove(i)}
                      title="Delete"
                      className="text-red-700 hover:underline text-xs"
                    >delete</button>
                  )}
                </td>
              </tr>
            );
          })}
          {rules.length === 0 && (
            <tr>
              <td colSpan={8} className="px-3 py-6 text-center text-slate-500">
                No rules. {!readOnly && 'Add at least one rule with path "/*".'}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
