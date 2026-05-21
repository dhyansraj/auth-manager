import { useEffect, useState } from 'react';
import { useAuth } from 'react-oidc-context';

type Order = {
  id: number;
  item: string;
  qty: number;
};

export default function Orders() {
  const auth = useAuth();
  const [orders, setOrders] = useState<Order[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!auth.isAuthenticated || !auth.user) return;
    setLoading(true);
    setError(null);
    fetch('/api/orders', {
      headers: { Authorization: `Bearer ${auth.user.access_token}` },
    })
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.text();
          throw new Error(`HTTP ${r.status} ${r.statusText}: ${body}`);
        }
        return r.json();
      })
      .then((data: Order[]) => {
        setOrders(data);
        setLoading(false);
      })
      .catch((e: Error) => {
        setError(e.message);
        setLoading(false);
      });
  }, [auth.isAuthenticated, auth.user]);

  if (!auth.isAuthenticated) {
    return (
      <div className="bg-yellow-50 border border-yellow-200 rounded p-4 text-yellow-900">
        Sign in to view orders.
        <button
          onClick={() => auth.signinRedirect()}
          className="ml-3 text-sm underline"
        >
          Sign in
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Orders</h1>
      {loading && <div className="text-slate-500">Loading…</div>}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded p-4 text-red-800 whitespace-pre-wrap text-sm font-mono">
          {error}
        </div>
      )}
      {orders && (
        <table className="w-full bg-white border rounded shadow-sm">
          <thead className="bg-slate-100 text-slate-700 text-left text-sm">
            <tr>
              <th className="px-4 py-2">ID</th>
              <th className="px-4 py-2">Item</th>
              <th className="px-4 py-2">Qty</th>
            </tr>
          </thead>
          <tbody>
            {orders.map((o) => (
              <tr key={o.id} className="border-t text-sm">
                <td className="px-4 py-2 font-mono">{o.id}</td>
                <td className="px-4 py-2">{o.item}</td>
                <td className="px-4 py-2">{o.qty}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
