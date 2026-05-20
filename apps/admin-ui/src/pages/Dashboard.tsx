import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';

export default function Dashboard() {
  const tenants = useQuery({ queryKey: ['tenants'], queryFn: api.listTenants });
  const audit = useQuery({ queryKey: ['audit', 0, 5], queryFn: () => api.globalAudit(0, 5) });

  const stats = (tenants.data ?? []).reduce(
    (acc, t) => { acc[t.status] = (acc[t.status] ?? 0) + 1; return acc; },
    { ACTIVE: 0, PENDING: 0, FAILED: 0, SUSPENDED: 0, DELETED: 0 } as Record<string, number>
  );

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Dashboard</h1>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {Object.entries(stats).map(([k, v]) => (
          <div key={k} className="bg-white border rounded-lg p-4">
            <div className="text-xs text-slate-500 uppercase">{k}</div>
            <div className="text-2xl font-mono">{v}</div>
          </div>
        ))}
      </div>
      <div>
        <h2 className="text-lg font-semibold mb-2">Recent activity</h2>
        {audit.isLoading ? <div>Loading…</div> :
          audit.isError ? <div className="text-red-700">Error: {String(audit.error)}</div> :
          <ul className="space-y-2">
            {audit.data!.items.map(e => (
              <li key={e.id} className="bg-white border rounded p-3 text-sm flex justify-between">
                <div>
                  <span className={'font-mono ' + (e.result === 'SUCCESS' ? 'text-emerald-700' : 'text-red-700')}>{e.result}</span>
                  <span className="ml-2 font-semibold">{e.action}</span>
                  {e.targetId && <span className="ml-2 text-slate-500 font-mono text-xs">{e.targetId.slice(0,8)}</span>}
                </div>
                <div className="text-slate-500">{new Date(e.occurredAt).toLocaleString()}</div>
              </li>
            ))}
            {audit.data!.items.length === 0 && <li className="text-slate-500">No activity yet</li>}
          </ul>
        }
      </div>
    </div>
  );
}
