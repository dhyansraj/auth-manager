import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { usePermission } from '@mcpmesh/auth-lib-react';
import { api } from '../../api/client';
import type { DatabaseProvisionResult } from '../../api/types';
import ConfirmDialog from '../../components/ConfirmDialog';
import { useToast } from '../../components/Toast';

interface Props {
  tenantId: string;
  slug: string;
}

/**
 * Operator-driven managed data services for a tenant. Round 1 covers
 * Postgres only — provision / deprovision a database on the shared CNPG
 * cluster. Credentials are revealed ONCE on provision; subsequent visits
 * show only the connection coordinates (no password).
 */
export default function DataServicesTab({ tenantId, slug }: Props) {
  const canManage = usePermission('TENANT_EDIT');
  const qc = useQueryClient();
  const toast = useToast();
  const [confirmDeprovision, setConfirmDeprovision] = useState(false);

  const status = useQuery({
    queryKey: ['tenant-db', tenantId],
    queryFn: () => api.getDatabaseStatus(tenantId),
    enabled: !!tenantId,
  });

  const [revealed, setRevealed] = useState<DatabaseProvisionResult | null>(null);

  const provision = useMutation({
    mutationFn: () => api.provisionDatabase(tenantId),
    onSuccess: (data) => {
      setRevealed(data);
      qc.invalidateQueries({ queryKey: ['tenant-db', tenantId] });
    },
  });

  const deprovision = useMutation({
    mutationFn: () => api.deprovisionDatabase(tenantId),
    onSuccess: () => {
      setRevealed(null);
      qc.invalidateQueries({ queryKey: ['tenant-db', tenantId] });
      setConfirmDeprovision(false);
      toast.success('Database deprovisioned');
    },
    onError: (err) => {
      setConfirmDeprovision(false);
      toast.error(`Deprovision failed: ${err instanceof Error ? err.message : String(err)}`);
    },
  });

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">Data Services</h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Shared HA infrastructure for tenant apps. Provision a dedicated
          database on the platform&apos;s 3-node Postgres cluster instead
          of running your own.
        </p>
      </div>

      {status.isLoading && <div>Loading…</div>}
      {status.isError && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
          {String(status.error)}
        </div>
      )}

      {status.data && (
        <div className="bg-white border rounded p-4 space-y-3">
          <h3 className="font-semibold">Postgres</h3>

          {!status.data.provisioned && !revealed && (
            <>
              <p className="text-sm text-slate-600">
                No managed Postgres database for this tenant. Provision one to get:
              </p>
              <ul className="list-disc ml-5 text-sm text-slate-600">
                <li>3-replica synchronous-replication HA</li>
                <li>Automated backups</li>
                <li>Connection from any namespace via cluster DNS</li>
                <li>Connection limit: 50 per user</li>
              </ul>
              <button
                type="button"
                onClick={() => provision.mutate()}
                disabled={!canManage || provision.isPending}
                className="bg-slate-900 text-white px-4 py-2 rounded text-sm hover:bg-slate-700 disabled:opacity-50"
                title={canManage ? undefined : 'Requires TENANT_EDIT'}
              >
                {provision.isPending ? 'Provisioning…' : 'Provision database'}
              </button>
              {provision.isError && (
                <div className="text-red-700 text-xs mt-1">{String(provision.error)}</div>
              )}
            </>
          )}

          {revealed && (
            <div className="space-y-3">
              <div className="bg-amber-50 border border-amber-200 rounded p-3 text-sm text-amber-900">
                <strong>Save these credentials NOW.</strong> The password is shown
                only once and cannot be retrieved later. If lost, deprovision and
                reprovision to get new credentials.
              </div>
              <CredentialField label="Host" value={revealed.host} mono />
              <CredentialField label="Port" value={String(revealed.port)} mono />
              <CredentialField label="Database" value={revealed.database} mono />
              <CredentialField label="Username" value={revealed.username} mono />
              <CredentialField label="Password" value={revealed.password} mono secret />
              <CredentialField label="JDBC URL" value={revealed.jdbcUrl} mono />
              <button
                type="button"
                onClick={() => setRevealed(null)}
                className="text-sm text-slate-500 hover:text-slate-700 underline"
              >
                I&apos;ve saved these — hide
              </button>
            </div>
          )}

          {status.data.provisioned && !revealed && (
            <>
              <div className="text-sm text-slate-600">
                Database provisioned. Credentials are shown only at provisioning
                time; if you&apos;ve lost the password, deprovision + reprovision
                to mint new ones.
              </div>
              <div className="grid grid-cols-[140px_1fr] gap-y-1 gap-x-3 text-sm">
                <div className="text-slate-500">Host</div>
                <div className="font-mono">{status.data.host}</div>
                <div className="text-slate-500">Port</div>
                <div className="font-mono">{status.data.port}</div>
                <div className="text-slate-500">Database</div>
                <div className="font-mono">{status.data.database}</div>
                <div className="text-slate-500">Username</div>
                <div className="font-mono">{status.data.username}</div>
                <div className="text-slate-500">Password</div>
                <div className="text-slate-400">(only shown at provisioning time)</div>
              </div>
              {canManage && (
                <button
                  type="button"
                  onClick={() => setConfirmDeprovision(true)}
                  disabled={deprovision.isPending}
                  className="text-red-700 hover:underline text-xs disabled:opacity-50"
                >
                  {deprovision.isPending ? 'Deprovisioning…' : 'Deprovision database'}
                </button>
              )}
              {deprovision.isError && (
                <div className="text-red-700 text-xs">{String(deprovision.error)}</div>
              )}
            </>
          )}
        </div>
      )}

      <ConfirmDialog
        isOpen={confirmDeprovision}
        title="Deprovision the database for this tenant?"
        description="This DROPs the database — ALL DATA IS LOST. Cannot be undone."
        confirmLabel="Deprovision"
        danger
        requireText={slug}
        isLoading={deprovision.isPending}
        onCancel={() => setConfirmDeprovision(false)}
        onConfirm={() => deprovision.mutate()}
      />
    </div>
  );
}

function CredentialField({
  label,
  value,
  mono,
  secret,
}: {
  label: string;
  value: string;
  mono?: boolean;
  secret?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  const [show, setShow] = useState(!secret);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // no-op: clipboard may be unavailable in non-secure contexts
    }
  };
  return (
    <div className="grid grid-cols-[140px_1fr_auto_auto] gap-2 items-center text-sm">
      <div className="text-slate-500">{label}</div>
      <div className={(mono ? 'font-mono ' : '') + 'break-all'}>
        {show ? value : '•'.repeat(Math.min(value.length, 16))}
      </div>
      {secret && (
        <button
          type="button"
          onClick={() => setShow((s) => !s)}
          className="text-xs text-slate-600 hover:text-slate-900 underline"
        >
          {show ? 'hide' : 'show'}
        </button>
      )}
      {!secret && <div />}
      <button
        type="button"
        onClick={onCopy}
        className="text-xs bg-white border rounded px-2 py-0.5 hover:bg-slate-50"
      >
        {copied ? 'copied' : 'copy'}
      </button>
    </div>
  );
}
