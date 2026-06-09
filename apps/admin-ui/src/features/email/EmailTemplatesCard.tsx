import { useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { usePermission } from '@mcpmesh/auth-lib-react';
import { api, ApiError } from '../../api/client';
import type { EmailTemplateSummary } from '../../api/types';

const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;
const TYPE_KEY_RE = /^[a-z0-9-]{1,64}$/;

interface Props {
  slug: string;
}

export default function EmailTemplatesCard({ slug }: Props) {
  // EMAIL_EDIT gates writes (POST/PUT/DELETE); reads need only TENANT_VIEW
  // which the tab is already gated on at TenantDetail.
  const canEdit = usePermission('EMAIL_EDIT');
  const qc = useQueryClient();

  const templates = useQuery({
    queryKey: ['email-templates', slug],
    queryFn: () => api.listEmailTemplates(slug),
    enabled: !!slug,
  });

  // Upload target: null = no upload modal open; typeKey + exists drive POST/PUT.
  const [uploadTarget, setUploadTarget] = useState<
    { typeKey: string; exists: boolean } | null
  >(null);
  const [previewKey, setPreviewKey] = useState<string | null>(null);
  const [showNew, setShowNew] = useState(false);

  function invalidate() {
    qc.invalidateQueries({ queryKey: ['email-templates', slug] });
  }

  const del = useMutation({
    mutationFn: (typeKey: string) => api.deleteEmailTemplate(slug, typeKey),
    onSuccess: () => invalidate(),
  });

  function downloadStarter() {
    void api.downloadEmailTemplateStarter(slug);
  }

  return (
    <div className="space-y-3">
      <div>
        <h3 className="text-base font-semibold">Email templates</h3>
        <p className="text-xs text-slate-500 mt-0.5">
          Override Keycloak&apos;s outbound email templates (verify email,
          password reset, invites, …) with your own branded HTML. Download the
          starter, edit the subject + HTML and drop in any images locally inside
          the zip, then upload. We pre-scan every file before applying.
        </p>
      </div>

      <div className="flex gap-3">
        <button
          type="button"
          onClick={downloadStarter}
          className="bg-slate-900 text-white px-3 py-1.5 rounded text-sm hover:bg-slate-700"
        >
          Download starter
        </button>
        {canEdit && (
          <button
            type="button"
            onClick={() => setShowNew(true)}
            className="bg-white border px-3 py-1.5 rounded text-sm hover:bg-slate-50"
          >
            + New template
          </button>
        )}
      </div>

      {templates.isLoading && <div className="text-sm text-slate-500">Loading…</div>}
      {templates.isError && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
          {String(templates.error)}
        </div>
      )}

      {templates.data && (
        <TemplatesTable
          rows={templates.data}
          canEdit={canEdit}
          deleting={del.isPending ? del.variables ?? null : null}
          onPreview={(k) => setPreviewKey(k)}
          onReplace={(k) => setUploadTarget({ typeKey: k, exists: true })}
          onDelete={(k) => {
            if (confirm(`Delete the "${k}" email template? KC falls back to its default.`)) {
              del.mutate(k);
            }
          }}
        />
      )}

      {del.isError && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
          {String(del.error)}
        </div>
      )}

      {showNew && (
        <NewTemplateModal
          existing={templates.data ?? []}
          onCancel={() => setShowNew(false)}
          onCreate={(typeKey) => {
            setShowNew(false);
            setUploadTarget({ typeKey, exists: false });
          }}
        />
      )}

      {uploadTarget && (
        <UploadModal
          slug={slug}
          typeKey={uploadTarget.typeKey}
          exists={uploadTarget.exists}
          onClose={() => setUploadTarget(null)}
          onUploaded={() => {
            setUploadTarget(null);
            invalidate();
          }}
        />
      )}

      {previewKey && (
        <PreviewModal
          slug={slug}
          typeKey={previewKey}
          onClose={() => setPreviewKey(null)}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Table
// ---------------------------------------------------------------------------

function TemplatesTable({
  rows, canEdit, deleting, onPreview, onReplace, onDelete,
}: {
  rows: EmailTemplateSummary[];
  canEdit: boolean;
  deleting: string | null;
  onPreview: (typeKey: string) => void;
  onReplace: (typeKey: string) => void;
  onDelete: (typeKey: string) => void;
}) {
  if (rows.length === 0) {
    return (
      <div className="bg-white border rounded p-4 text-sm text-slate-500">
        No custom templates. Keycloak uses its built-in defaults for every email
        type until you upload one.
      </div>
    );
  }
  return (
    <div className="bg-white border rounded overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b bg-slate-50 text-left text-xs text-slate-500">
            <th className="px-3 py-2 font-medium">Type</th>
            <th className="px-3 py-2 font-medium">Assets</th>
            <th className="px-3 py-2 font-medium">Last updated</th>
            <th className="px-3 py-2 font-medium text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.typeKey} className="border-b last:border-0">
              <td className="px-3 py-2 font-mono">{r.typeKey}</td>
              <td className="px-3 py-2">
                {r.hasAssets
                  ? <span className="text-emerald-700">✓ yes</span>
                  : <span className="text-slate-400">—</span>}
              </td>
              <td className="px-3 py-2 text-slate-600">
                {r.updatedAt ? new Date(r.updatedAt).toLocaleString() : '—'}
              </td>
              <td className="px-3 py-2">
                <div className="flex gap-3 justify-end">
                  <button
                    type="button"
                    onClick={() => onPreview(r.typeKey)}
                    className="text-slate-700 hover:underline text-xs"
                  >
                    Preview
                  </button>
                  {canEdit && (
                    <button
                      type="button"
                      onClick={() => onReplace(r.typeKey)}
                      className="text-slate-700 hover:underline text-xs"
                    >
                      Replace
                    </button>
                  )}
                  {canEdit && (
                    <button
                      type="button"
                      onClick={() => onDelete(r.typeKey)}
                      disabled={deleting === r.typeKey}
                      className="text-red-700 hover:underline text-xs disabled:opacity-50"
                    >
                      {deleting === r.typeKey ? 'Deleting…' : 'Delete'}
                    </button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// New-template modal: validates the typeKey slug, then hands off to upload.
// ---------------------------------------------------------------------------

function NewTemplateModal({
  existing, onCancel, onCreate,
}: {
  existing: EmailTemplateSummary[];
  onCancel: () => void;
  onCreate: (typeKey: string) => void;
}) {
  const [value, setValue] = useState('');
  const trimmed = value.trim().toLowerCase();
  const taken = existing.some((r) => r.typeKey === trimmed);
  const valid = TYPE_KEY_RE.test(trimmed) && !taken;
  const error =
    trimmed === '' ? null
    : !TYPE_KEY_RE.test(trimmed) ? 'Use lowercase letters, digits and hyphens (1–64 chars).'
    : taken ? 'A template with this type already exists.'
    : null;

  return (
    <Modal title="New email template" onClose={onCancel}>
      <div className="space-y-3">
        <label className="block space-y-1">
          <div className="text-xs text-slate-600">Template type key</div>
          <input
            autoFocus
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && valid) onCreate(trimmed); }}
            placeholder="e.g. password-reset"
            className="w-full border rounded px-2 py-1 text-sm font-mono"
          />
          <div className="text-xs text-slate-500">
            Lowercase slug matching the KC email type (e.g.{' '}
            <code className="font-mono">email-verification</code>,{' '}
            <code className="font-mono">password-reset</code>).
          </div>
          {error && <div className="text-red-700 text-xs">{error}</div>}
        </label>
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="text-sm text-slate-600 hover:text-slate-900 px-3 py-1.5"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => onCreate(trimmed)}
            disabled={!valid}
            className="bg-slate-900 text-white px-3 py-1.5 rounded text-sm hover:bg-slate-700 disabled:opacity-50"
          >
            Continue
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Upload modal: drop-zip uploader (mirrors the branding UploadZone UX).
// ---------------------------------------------------------------------------

function UploadModal({
  slug, typeKey, exists, onClose, onUploaded,
}: {
  slug: string;
  typeKey: string;
  exists: boolean;
  onClose: () => void;
  onUploaded: () => void;
}) {
  const upload = useMutation({
    mutationFn: (file: File) => api.uploadEmailTemplate(slug, typeKey, file, exists),
    onSuccess: () => onUploaded(),
  });

  return (
    <Modal
      title={`${exists ? 'Replace' : 'Upload'} template — ${typeKey}`}
      onClose={onClose}
    >
      <div className="space-y-3">
        <p className="text-xs text-slate-500">
          Drop the edited <code className="font-mono">.zip</code> (subject +
          HTML + any inline images) to {exists ? 'replace' : 'create'} the{' '}
          <code className="font-mono">{typeKey}</code> template.
        </p>
        <UploadZone
          typeKey={typeKey}
          uploading={upload.isPending}
          onUpload={(f) => upload.mutate(f)}
        />
        {upload.isError && <UploadErrorPanel error={upload.error} />}
        <div className="flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="text-sm text-slate-600 hover:text-slate-900 px-3 py-1.5"
          >
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
}

function UploadZone({
  typeKey, uploading, onUpload,
}: {
  typeKey: string;
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
      title={`Drop or click to upload a zip for ${typeKey}`}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".zip,application/zip,application/x-zip-compressed"
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) tryUpload(f);
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
        Max 5 MB. We prescan every file before applying it.
      </div>
      {localError && (
        <div className="text-red-700 text-xs mt-2">{localError}</div>
      )}
    </div>
  );
}

function UploadErrorPanel({ error }: { error: unknown }) {
  if (error instanceof ApiError && error.status === 400 && typeof error.body === 'object' && error.body) {
    const body = error.body as { detail?: string; message?: string };
    return (
      <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
        {body.detail ?? body.message ?? String(error)}
      </div>
    );
  }
  return (
    <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
      {String(error)}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Preview modal: renders the server-fetched HTML in a sandboxed iframe.
// ---------------------------------------------------------------------------

function PreviewModal({
  slug, typeKey, onClose,
}: {
  slug: string;
  typeKey: string;
  onClose: () => void;
}) {
  const preview = useQuery({
    queryKey: ['email-template', slug, typeKey],
    queryFn: () => api.emailTemplatePreview(slug, typeKey),
  });

  return (
    <Modal title={`Preview — ${typeKey}`} onClose={onClose} wide>
      {preview.isLoading && <div className="text-sm text-slate-500">Rendering…</div>}
      {preview.isError && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
          {String(preview.error)}
        </div>
      )}
      {preview.data !== undefined && (
        <iframe
          title={`Preview of ${typeKey}`}
          srcDoc={preview.data}
          sandbox=""
          className="w-full h-[60vh] border rounded bg-white"
        />
      )}
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Shared bits
// ---------------------------------------------------------------------------

function Modal({
  title, onClose, children, wide,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  wide?: boolean;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/30 p-4 overflow-y-auto"
      onClick={onClose}
    >
      <div
        className={'bg-white rounded shadow-lg w-full mt-16 ' + (wide ? 'max-w-3xl' : 'max-w-md')}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b px-4 py-3">
          <h4 className="text-sm font-semibold">{title}</h4>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 text-lg leading-none"
            aria-label="Close"
          >
            ×
          </button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}
