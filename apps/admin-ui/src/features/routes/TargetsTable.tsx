import type { TargetError } from './validate';

export interface TargetEntry {
  key: string;
  value: string;
}

interface Props {
  targets: TargetEntry[];
  duplicateKeys: Set<string>;
  targetErrors: TargetError[];
  readOnly: boolean;
  onChange: (targets: TargetEntry[]) => void;
}

export default function TargetsTable({ targets, duplicateKeys, targetErrors, readOnly, onChange }: Props) {
  const update = (i: number, patch: Partial<TargetEntry>) => {
    const next = targets.map((t, idx) => (idx === i ? { ...t, ...patch } : t));
    onChange(next);
  };

  const remove = (i: number) => {
    onChange(targets.filter((_, idx) => idx !== i));
  };

  const add = () => {
    onChange([...targets, { key: '', value: '' }]);
  };

  const valueErrFor = (key: string) => targetErrors.find(e => e.key === key)?.message;

  return (
    <div className="space-y-2">
      <div className="flex justify-between items-center">
        <h2 className="text-lg font-semibold">Targets</h2>
        {!readOnly && (
          <button
            type="button"
            onClick={add}
            className="bg-slate-900 text-white px-3 py-1 rounded text-sm hover:bg-slate-700"
          >
            + Add target
          </button>
        )}
      </div>
      <table className="w-full bg-white border rounded text-sm">
        <thead className="bg-slate-50 text-left">
          <tr>
            <th className="px-3 py-2 w-48">Name</th>
            <th className="px-3 py-2">Service URL</th>
            <th className="px-3 py-2 w-20 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {targets.map((t, i) => {
            const keyEmpty = !t.key || t.key.trim() === '';
            const dup = !keyEmpty && duplicateKeys.has(t.key);
            const valErr = valueErrFor(t.key);
            const valEmpty = !t.value || t.value.trim() === '';
            return (
              <tr key={i} className="border-t align-top">
                <td className="px-3 py-2">
                  <input
                    type="text"
                    value={t.key}
                    placeholder="backend"
                    disabled={readOnly}
                    onChange={e => update(i, { key: e.target.value })}
                    className={
                      'w-full border rounded px-2 py-1 text-sm font-mono disabled:bg-slate-100 ' +
                      (keyEmpty || dup ? 'border-red-400' : '')
                    }
                  />
                  {keyEmpty && <div className="text-xs text-red-700 mt-1">Name is required</div>}
                  {dup && <div className="text-xs text-red-700 mt-1">Duplicate name</div>}
                </td>
                <td className="px-3 py-2">
                  <input
                    type="text"
                    value={t.value}
                    placeholder="service.namespace.svc.cluster.local:8080"
                    disabled={readOnly}
                    onChange={e => update(i, { value: e.target.value })}
                    className={
                      'w-full border rounded px-2 py-1 text-sm font-mono disabled:bg-slate-100 ' +
                      (valEmpty || valErr ? 'border-red-400' : '')
                    }
                  />
                  {valEmpty && <div className="text-xs text-red-700 mt-1">URL is required</div>}
                  {valErr && !valEmpty && <div className="text-xs text-red-700 mt-1">{valErr}</div>}
                </td>
                <td className="px-3 py-2 text-right">
                  {!readOnly && (
                    <button
                      type="button"
                      onClick={() => remove(i)}
                      className="text-red-700 hover:underline text-xs"
                    >delete</button>
                  )}
                </td>
              </tr>
            );
          })}
          {targets.length === 0 && (
            <tr>
              <td colSpan={3} className="px-3 py-6 text-center text-slate-500">
                No targets. {!readOnly && 'Add at least one target to reference from rules.'}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
