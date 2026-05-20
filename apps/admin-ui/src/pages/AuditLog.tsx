import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';

export default function AuditLog() {
  const audit = useQuery({ queryKey: ['audit', 'global'], queryFn: () => api.globalAudit(0, 100) });

  return (
    <div className="space-y-3">
      <h1 className="text-2xl font-semibold">Audit log</h1>
      {audit.isLoading && <div>Loading…</div>}
      {audit.isError && <div className="text-red-700">{String(audit.error)}</div>}
      <table className="w-full bg-white border rounded text-sm">
        <thead className="bg-slate-50 text-left">
          <tr>
            <th className="px-3 py-2">When</th>
            <th className="px-3 py-2">Action</th>
            <th className="px-3 py-2">Result</th>
            <th className="px-3 py-2">Tenant</th>
            <th className="px-3 py-2">Target</th>
            <th className="px-3 py-2">Details</th>
          </tr>
        </thead>
        <tbody>
          {(audit.data?.items ?? []).map(e => (
            <tr key={e.id} className="border-t align-top">
              <td className="px-3 py-2 text-xs text-slate-500">{new Date(e.occurredAt).toLocaleString()}</td>
              <td className="px-3 py-2 font-mono">{e.action}</td>
              <td className="px-3 py-2"><span className={'font-medium ' + (e.result === 'SUCCESS' ? 'text-emerald-700' : 'text-red-700')}>{e.result}</span></td>
              <td className="px-3 py-2 font-mono text-xs">{e.tenantId?.slice(0,8) ?? '—'}</td>
              <td className="px-3 py-2 font-mono text-xs">{e.targetId?.slice(0,8) ?? '—'}</td>
              <td className="px-3 py-2 text-xs">
                {Object.keys(e.details).length > 0 ? (
                  <details>
                    <summary className="cursor-pointer text-slate-600">expand</summary>
                    <pre className="text-xs mt-1">{JSON.stringify(e.details, null, 2)}</pre>
                  </details>
                ) : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
