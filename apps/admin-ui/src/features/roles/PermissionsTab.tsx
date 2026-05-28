import { useMemo, useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { usePermission } from '@mcpmesh/auth-lib-react';
import type { PermissionDto } from '../../api/types';
import { api, ApiError } from '../../api/client';
import { permissionsQueryKey, rolesQueryKey, usePermissionsQuery } from './useRolesQuery';

const MAX_MANIFEST_BYTES = 1 * 1024 * 1024;  // 1 MB — generous for YAML

interface Props {
  /** Tenant UUID — used for the new UUID-keyed manifest endpoints. */
  id: string;
  /** Tenant slug — used for the slug-keyed permissions list query. */
  slug: string;
}

interface ApplyDiff {
  created?: string[];
  updated?: string[];
  unchanged?: string[];
  skipped?: string[];
  deleted?: string[];
}

interface ApplyResult {
  dryRun: boolean;
  permissions?: ApplyDiff;
  roles?: ApplyDiff;
  identityProviders?: ApplyDiff;
  defaultRoleMappers?: ApplyDiff;
  warnings?: string[];
}

export default function PermissionsTab({ id, slug }: Props) {
  const canManage = usePermission('PERMISSIONS_EDIT');
  const query = usePermissionsQuery(slug);
  const qc = useQueryClient();

  const inputRef = useRef<HTMLInputElement | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [showUpload, setShowUpload] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<ApplyResult | null>(null);

  const grouped = useMemo(() => groupByClient(query.data ?? []), [query.data]);

  const downloadMut = useMutation({
    mutationFn: () => api.downloadManifest(id),
  });

  const uploadMut = useMutation({
    mutationFn: async (file: File): Promise<ApplyResult> => {
      const text = await file.text();
      return (await api.uploadManifest(id, text)) as ApplyResult;
    },
    onSuccess: (result) => {
      setLastResult(result);
      // Permissions + roles likely changed; refresh both.
      qc.invalidateQueries({ queryKey: permissionsQueryKey(slug) });
      qc.invalidateQueries({ queryKey: rolesQueryKey(slug) });
    },
  });

  function tryUpload(file: File) {
    setLocalError(null);
    setLastResult(null);
    const lower = file.name.toLowerCase();
    if (!lower.endsWith('.yaml') && !lower.endsWith('.yml')) {
      setLocalError('Only .yaml / .yml files are accepted');
      return;
    }
    if (file.size > MAX_MANIFEST_BYTES) {
      setLocalError(`File is too large (${formatBytes(file.size)}); max is ${formatBytes(MAX_MANIFEST_BYTES)}`);
      return;
    }
    uploadMut.mutate(file);
  }

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">Permissions</h2>
          <p className="text-xs text-slate-500 mt-1">
            Defined by your app's permission manifest. Download to edit in
            your repo; upload to apply changes.
          </p>
        </div>
        <div className="flex gap-2 shrink-0">
          <button
            onClick={() => {
              setLocalError(null);
              setLastResult(null);
              downloadMut.mutate();
            }}
            disabled={downloadMut.isPending}
            className="bg-white border px-3 py-1.5 rounded text-sm hover:bg-slate-50 disabled:opacity-50"
          >
            {downloadMut.isPending ? 'Downloading…' : 'Download manifest'}
          </button>
          {canManage && (
            <button
              onClick={() => setShowUpload(v => !v)}
              className="bg-slate-900 text-white px-3 py-1.5 rounded text-sm hover:bg-slate-700"
            >
              {showUpload ? 'Hide uploader' : 'Upload manifest'}
            </button>
          )}
        </div>
      </div>

      {downloadMut.isError && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
          Download failed: {String(downloadMut.error)}
        </div>
      )}

      {canManage && showUpload && (
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            const f = e.dataTransfer.files?.[0];
            if (f) tryUpload(f);
          }}
          className={
            'border-2 border-dashed rounded p-6 text-center cursor-pointer transition-colors ' +
            (dragOver ? 'border-slate-900 bg-slate-50' : 'border-slate-300 bg-white hover:border-slate-500')
          }
          onClick={() => inputRef.current?.click()}
          title="Drop or click to upload a manifest YAML"
        >
          <input
            ref={inputRef}
            type="file"
            accept=".yaml,.yml,application/yaml,application/x-yaml,text/yaml,text/plain"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) tryUpload(f);
              if (inputRef.current) inputRef.current.value = '';
            }}
          />
          <div className="text-sm text-slate-700">
            {uploadMut.isPending
              ? 'Uploading…'
              : <>Drop your <code className="font-mono">.yaml</code> here, or click to pick a file</>
            }
          </div>
          <div className="text-xs text-slate-500 mt-1">
            Max {formatBytes(MAX_MANIFEST_BYTES)}. Applies permissions + roles + identity providers
            and default roles in one shot.
          </div>
          {localError && (
            <div className="text-red-700 text-xs mt-2">{localError}</div>
          )}
        </div>
      )}

      {uploadMut.isError && (
        <UploadErrorPanel error={uploadMut.error} />
      )}

      {lastResult && (
        <ApplyResultPanel result={lastResult} onDismiss={() => setLastResult(null)} />
      )}

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

function ApplyResultPanel({ result, onDismiss }: { result: ApplyResult; onDismiss: () => void }) {
  const sections: Array<[string, ApplyDiff | undefined]> = [
    ['Permissions', result.permissions],
    ['Roles', result.roles],
    ['Identity providers', result.identityProviders],
    ['Default-role mappers', result.defaultRoleMappers],
  ];
  return (
    <div className="bg-emerald-50 border border-emerald-200 rounded p-3 text-sm text-emerald-900">
      <div className="flex justify-between items-start">
        <div className="font-medium">
          Manifest applied{result.dryRun ? ' (dry run)' : ''}.
        </div>
        <button onClick={onDismiss} className="text-emerald-700 hover:underline text-xs">
          dismiss
        </button>
      </div>
      <div className="mt-2 space-y-1.5">
        {sections.map(([label, diff]) => diff && <DiffLine key={label} label={label} diff={diff} />)}
      </div>
      {result.warnings && result.warnings.length > 0 && (
        <div className="mt-2 border-t border-emerald-200 pt-2">
          <div className="text-xs font-medium">Warnings:</div>
          <ul className="text-xs list-disc ml-5">
            {result.warnings.map((w, i) => <li key={i}>{w}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}

function DiffLine({ label, diff }: { label: string; diff: ApplyDiff }) {
  const parts: string[] = [];
  if (diff.created?.length)   parts.push(`${diff.created.length} created`);
  if (diff.updated?.length)   parts.push(`${diff.updated.length} updated`);
  if (diff.unchanged?.length) parts.push(`${diff.unchanged.length} unchanged`);
  if (diff.skipped?.length)   parts.push(`${diff.skipped.length} skipped`);
  if (diff.deleted?.length)   parts.push(`${diff.deleted.length} deleted`);
  if (parts.length === 0) parts.push('no changes');
  return (
    <div className="text-xs">
      <span className="font-medium">{label}:</span> {parts.join(', ')}
    </div>
  );
}

function UploadErrorPanel({ error }: { error: unknown }) {
  if (error instanceof ApiError && error.body) {
    return (
      <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
        <div className="font-medium">Apply failed (HTTP {error.status})</div>
        <pre className="text-xs mt-1 whitespace-pre-wrap break-all">
          {typeof error.body === 'string' ? error.body : JSON.stringify(error.body, null, 2)}
        </pre>
      </div>
    );
  }
  return (
    <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
      {String(error)}
    </div>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
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
