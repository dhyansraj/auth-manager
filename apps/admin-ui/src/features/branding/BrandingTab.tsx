import { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { bffFetch, usePermission } from '@mcpmesh/auth-lib-react';
import { api, ApiError } from '../../api/client';
import type {
  BrandingConfig,
  LayoutVariant,
  ThemeMeta,
  ThemeValidationError,
} from '../../api/types';

const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;

interface Props {
  slug: string;
}

export default function BrandingTab({ slug }: Props) {
  const canManage = usePermission('BRANDING_EDIT');
  const qc = useQueryClient();

  const meta = useQuery({
    queryKey: ['theme', slug],
    queryFn: () => api.getThemeMeta(slug),
    enabled: !!slug,
  });

  // Poll status every 2s while rolling out; idle otherwise.
  const status = useQuery({
    queryKey: ['theme-status', slug],
    queryFn: () => api.getThemeStatus(slug),
    enabled: !!slug,
    refetchInterval: (q) =>
      q.state.data?.state === 'ROLLING_OUT' ? 2000 : false,
  });

  const upload = useMutation({
    mutationFn: (file: File) => api.uploadTheme(slug, file),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['theme', slug] });
      qc.invalidateQueries({ queryKey: ['theme-status', slug] });
      // Upload may have updated the tenant's layoutVariant (server-side
      // reconcile from mcpLayoutVariant= in the uploaded zip). Refresh the
      // branding query so the layout dropdown stays in sync.
      qc.invalidateQueries({ queryKey: ['branding', slug] });
    },
  });

  const del = useMutation({
    mutationFn: () => api.deleteTheme(slug),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['theme', slug] });
      qc.invalidateQueries({ queryKey: ['theme-status', slug] });
    },
  });

  function downloadStarter() {
    // Backend requires auth; cookies can't be set on a plain <a download>
    // cross-page navigation reliably, so fetch + blob + synthetic anchor.
    // bffFetch attaches the session cookie automatically.
    void (async () => {
      const r = await bffFetch(api.themeStarterUrl(slug));
      if (!r.ok) throw new Error(`Starter download failed: HTTP ${r.status}`);
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `t-${slug}-starter.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    })();
  }

  return (
    <div className="space-y-3">
      <div>
        <h2 className="text-lg font-semibold">Branding</h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Customize this tenant&apos;s Keycloak login + account pages with your
          own CSS, logo, fonts, and copy. Pick a layout, download the
          layout-aware starter, edit slot HTML locally inside the zip, then
          upload. We pre-scan every file and reject anything that could execute
          code in the user&apos;s browser.
        </p>
      </div>

      {!canManage && (
        <div className="bg-slate-50 border border-slate-200 rounded p-3 text-sm text-slate-700">
          You don&apos;t have permission to change branding for this tenant.
          The current theme is read-only below.
        </div>
      )}

      <LayoutPicker slug={slug} canManage={canManage} />

      <div className="flex gap-3">
        <button
          onClick={downloadStarter}
          className="bg-slate-900 text-white px-3 py-1.5 rounded text-sm hover:bg-slate-700"
        >
          Download starter
        </button>
      </div>

      {canManage && (
        <UploadZone
          slug={slug}
          uploading={upload.isPending}
          onUpload={(f) => upload.mutate(f)}
        />
      )}

      {upload.isError && (
        <UploadErrorPanel error={upload.error} />
      )}

      {meta.data && (
        <CurrentThemeCard
          meta={meta.data}
          canManage={canManage}
          onDelete={() => { if (confirm('Reset branding to default? This drops your custom theme.')) del.mutate(); }}
          deleting={del.isPending}
          status={status.data?.state ?? 'READY'}
          progress={status.data?.progress ?? 100}
        />
      )}

      {del.isError && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
          {String(del.error)}
        </div>
      )}
    </div>
  );
}

function CurrentThemeCard({
  meta, canManage, onDelete, deleting, status, progress,
}: {
  meta: ThemeMeta;
  canManage: boolean;
  onDelete: () => void;
  deleting: boolean;
  status: 'READY' | 'ROLLING_OUT' | 'FAILED';
  progress: number;
}) {
  return (
    <div className="bg-white border rounded p-4 space-y-2 text-sm">
      <div className="font-semibold">Current theme</div>
      {!meta.configured && (
        <div className="text-slate-500">No custom theme uploaded. Using the platform default.</div>
      )}
      {meta.configured && (
        <>
          <div className="grid grid-cols-[140px_1fr] gap-1">
            <div className="text-slate-500">Files</div>
            <div className="font-mono">{meta.fileCount}</div>
            <div className="text-slate-500">Total size</div>
            <div className="font-mono">{formatBytes(meta.totalBytes)}</div>
            <div className="text-slate-500">Last applied</div>
            <div>{meta.lastModified ? new Date(meta.lastModified).toLocaleString() : '—'}</div>
            <div className="text-slate-500">Status</div>
            <div>
              <StatusBadge state={status} progress={progress} />
            </div>
          </div>
          {canManage && (
            <button
              onClick={onDelete}
              disabled={deleting}
              className="text-red-700 hover:underline text-xs disabled:opacity-50 mt-2"
            >
              {deleting ? 'Resetting…' : 'Reset to default'}
            </button>
          )}
        </>
      )}
    </div>
  );
}

function StatusBadge({ state, progress }: { state: 'READY' | 'ROLLING_OUT' | 'FAILED'; progress: number }) {
  if (state === 'READY') {
    return <span className="text-emerald-700">Ready</span>;
  }
  if (state === 'FAILED') {
    return <span className="text-red-700">Failed</span>;
  }
  return (
    <span className="inline-flex items-center gap-2">
      <span className="inline-block h-2 w-24 bg-slate-200 rounded overflow-hidden">
        <span
          className="block h-full bg-amber-500 transition-all"
          style={{ width: `${progress}%` }}
        />
      </span>
      <span className="text-amber-700 text-xs">Rolling out {progress}%</span>
    </span>
  );
}

function UploadZone({
  slug, uploading, onUpload,
}: {
  slug: string;
  uploading: boolean;
  onUpload: (file: File) => void;
}) {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  function tryUpload(file: File) {
    setLocalError(null);
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setLocalError('Only .zip files are accepted');
      return;
    }
    if (file.size > MAX_UPLOAD_BYTES) {
      setLocalError(`File is too large (${formatBytes(file.size)}); max is ${formatBytes(MAX_UPLOAD_BYTES)}`);
      return;
    }
    onUpload(file);
  }

  return (
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
      title={`Drop or click to upload a theme zip for ${slug}`}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".zip,application/zip,application/x-zip-compressed"
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) tryUpload(f);
          // Reset so picking the same file twice still fires onChange.
          if (inputRef.current) inputRef.current.value = '';
        }}
      />
      <div className="text-sm text-slate-700">
        {uploading
          ? 'Uploading…'
          : <>Drop your <code className="font-mono">.zip</code> here, or click to pick a file</>
        }
      </div>
      <div className="text-xs text-slate-500 mt-1">
        Max 5 MB. We prescan for forbidden file types, remote URLs in CSS, and XSS in SVGs.
      </div>
      {localError && (
        <div className="text-red-700 text-xs mt-2">{localError}</div>
      )}
    </div>
  );
}

function UploadErrorPanel({ error }: { error: unknown }) {
  if (error instanceof ApiError && error.status === 400 && typeof error.body === 'object' && error.body) {
    const body = error.body as { errors?: ThemeValidationError[]; detail?: string };
    if (body.errors && body.errors.length > 0) {
      return (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
          <div className="font-medium">Your theme zip was rejected:</div>
          <ul className="list-disc ml-5 mt-1 space-y-0.5">
            {body.errors.map((e, i) => (
              <li key={i}>
                <code className="font-mono text-xs">{e.code}</code>
                {e.path && <> in <code className="font-mono text-xs">{e.path}</code></>}
                {': '}{e.message}
              </li>
            ))}
          </ul>
        </div>
      );
    }
    return (
      <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
        {body.detail ?? String(error)}
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

// ---------------------------------------------------------------------------
// Layout picker: auto-saves the layoutVariant via PUT /branding on every
// dropdown change. Slot HTML lives entirely inside the downloaded starter zip
// (zip-driven workflow); we do NOT render slot textareas here.
//
// We still send the existing `slots` map back on every save so the backend
// keeps whatever's already in the DB (legacy compat — the column stays).
// ---------------------------------------------------------------------------

const LAYOUT_OPTIONS: { value: LayoutVariant; label: string }[] = [
  { value: 'centered',    label: 'Centered (default)' },
  { value: 'split-left',  label: 'Split — marketing on left' },
  { value: 'split-right', label: 'Split — marketing on right' },
  { value: 'bleed',       label: 'Full-bleed background' },
];

function LayoutPicker({ slug, canManage }: { slug: string; canManage: boolean }) {
  const qc = useQueryClient();
  const branding = useQuery({
    queryKey: ['branding', slug],
    queryFn: () => api.getBranding(slug),
    enabled: !!slug,
  });

  const save = useMutation({
    mutationFn: (body: BrandingConfig) => api.updateBranding(slug, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['branding', slug] });
      // Layout change re-runs the theme apply, which may flip the rollout
      // status. Refresh both downstream queries so the badge updates.
      qc.invalidateQueries({ queryKey: ['theme', slug] });
      qc.invalidateQueries({ queryKey: ['theme-status', slug] });
    },
  });

  // "Saved" indicator fades in/out for ~1.5s after each successful save.
  const [savedFlash, setSavedFlash] = useState(false);
  useEffect(() => {
    if (!save.isSuccess) return;
    setSavedFlash(true);
    const t = setTimeout(() => setSavedFlash(false), 1500);
    return () => clearTimeout(t);
  }, [save.isSuccess, save.submittedAt]);

  function handleChange(next: LayoutVariant) {
    if (!branding.data) return;  // ignore until first load
    // Preserve whatever's in the DB for slots; the UI no longer owns them.
    save.mutate({ layoutVariant: next, slots: branding.data.slots ?? {} });
  }

  const current = branding.data?.layoutVariant ?? 'centered';
  const disabled = !canManage || save.isPending || branding.isLoading;

  return (
    <div className="bg-white border rounded p-4 space-y-2">
      <div>
        <div className="font-semibold">Layout</div>
        <p className="text-xs text-slate-500 mt-0.5">
          Pick a layout, then click <strong>Download starter</strong> below to
          get a zip with placeholder content for each slot.
        </p>
      </div>
      <div className="flex items-center gap-3">
        <select
          className="border rounded px-2 py-1 text-sm w-full max-w-sm disabled:bg-slate-100 disabled:text-slate-500"
          value={current}
          disabled={disabled}
          onChange={(e) => handleChange(e.target.value as LayoutVariant)}
        >
          {LAYOUT_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
        {save.isPending && (
          <span className="text-xs text-slate-500">Saving…</span>
        )}
        {!save.isPending && savedFlash && (
          <span className="text-xs text-emerald-700 transition-opacity">Saved</span>
        )}
        {save.isError && (
          <span className="text-xs text-red-700">
            {String(save.error)}
          </span>
        )}
      </div>
    </div>
  );
}
