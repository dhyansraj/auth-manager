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

  const move = (i: number, dir: -1 | 1) => {
    const j = i + dir;
    if (j < 0 || j >= rules.length) return;
    const next = [...rules];
    const tmp = next[i];
    next[i] = next[j];
    next[j] = tmp;
    onChange(next);
  };

  const remove = (i: number) => {
    onChange(rules.filter((_, idx) => idx !== i));
  };

  const add = () => {
    const defaultTarget = targetKeys[0] ?? '';
    onChange([...rules, { path: '', authMode: 'REQUIRED', target: defaultTarget }]);
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
      <table className="w-full bg-white border rounded text-sm">
        <thead className="bg-slate-50 text-left">
          <tr>
            <th className="px-3 py-2 w-10">#</th>
            <th className="px-3 py-2">Path</th>
            <th className="px-3 py-2 w-32">Auth Mode</th>
            <th className="px-3 py-2 w-48">Target</th>
            <th className="px-3 py-2 w-28 text-right">Actions</th>
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
                <td className="px-3 py-2 text-right whitespace-nowrap">
                  {!readOnly && (
                    <>
                      <button
                        type="button"
                        onClick={() => move(i, -1)}
                        disabled={i === 0}
                        title="Move up"
                        className="px-1 text-slate-500 hover:text-slate-900 disabled:opacity-30"
                      >↑</button>
                      <button
                        type="button"
                        onClick={() => move(i, 1)}
                        disabled={i === rules.length - 1}
                        title="Move down"
                        className="px-1 text-slate-500 hover:text-slate-900 disabled:opacity-30"
                      >↓</button>
                      <button
                        type="button"
                        onClick={() => remove(i)}
                        title="Delete"
                        className="ml-2 text-red-700 hover:underline text-xs"
                      >delete</button>
                    </>
                  )}
                </td>
              </tr>
            );
          })}
          {rules.length === 0 && (
            <tr>
              <td colSpan={5} className="px-3 py-6 text-center text-slate-500">
                No rules. {!readOnly && 'Add at least one rule with path "/*".'}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
