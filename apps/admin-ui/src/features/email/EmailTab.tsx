import { useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { usePermission } from '@mcpmesh/auth-lib-react';
import { api, ApiError } from '../../api/client';
import type {
  TenantEmailResponse,
  TenantEmailRateLimitResponse,
  DomainAuthResponse,
  DomainAuthCname,
  DomainAuthStatus,
} from '../../api/types';
import { useToast } from '../../components/Toast';
import EmailTemplatesCard from './EmailTemplatesCard';

interface Props {
  tenantId: string;
  slug: string;
}

export default function EmailTab({ tenantId, slug }: Props) {
  // TENANT_EDIT gates writes (PUT /email, POST /domain-auth); reads (GET) need
  // only TENANT_VIEW which the tab is already gated on at TenantDetail.
  const canManage = usePermission('TENANT_EDIT');
  const qc = useQueryClient();

  const email = useQuery({
    queryKey: ['tenant-email', tenantId],
    queryFn: () => api.getTenantEmail(tenantId),
    enabled: !!tenantId,
  });

  const domainAuth = useQuery({
    queryKey: ['tenant-domain-auth', tenantId],
    queryFn: () => api.getDomainAuthStatus(tenantId),
    enabled: !!tenantId,
  });

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold">Email</h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Configure where this tenant&apos;s outbound mail comes from. Override the
          platform default From address, set a tenant-branded display name, and
          authenticate your domain so SendGrid signs mail under your DKIM.
        </p>
      </div>

      {!canManage && (
        <div className="bg-slate-50 border border-slate-200 rounded p-3 text-sm text-slate-700">
          You don&apos;t have permission to change email settings for this tenant.
          The fields below are read-only.
        </div>
      )}

      {email.isLoading && <div>Loading…</div>}
      {email.isError && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
          {String(email.error)}
        </div>
      )}

      {email.data && (
        <EmailConfigCard
          tenantId={tenantId}
          email={email.data}
          canManage={canManage}
        />
      )}

      <hr className="border-slate-200" />

      <div>
        <h3 className="text-base font-semibold">Domain authentication</h3>
        <p className="text-xs text-slate-500 mt-0.5">
          Authenticate your domain so users see emails from your brand, not the
          platform fallback. We register the domain with SendGrid, push the 3
          DKIM CNAMEs into your Cloudflare zone (if it&apos;s in our CF
          account), and validate.
        </p>
      </div>

      {domainAuth.isLoading && <div>Loading…</div>}
      {domainAuth.isError && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
          {String(domainAuth.error)}
        </div>
      )}

      {domainAuth.data && email.data && (
        <DomainAuthCard
          tenantId={tenantId}
          email={email.data}
          domainAuth={domainAuth.data}
          canManage={canManage}
          onRefresh={() => {
            qc.invalidateQueries({ queryKey: ['tenant-email', tenantId] });
            qc.invalidateQueries({ queryKey: ['tenant-domain-auth', tenantId] });
          }}
        />
      )}

      <hr className="border-slate-200" />

      <div>
        <h3 className="text-base font-semibold">Send rate limits</h3>
        <p className="text-xs text-slate-500 mt-0.5">
          Caps on the tenant-app send API (per-minute burst + per-day quota).
          Defaults to the platform limits; set an override for high-volume
          tenants. Clearing an override falls back to the platform default.
        </p>
      </div>

      <RateLimitsCard tenantId={tenantId} canManage={canManage} />

      <hr className="border-slate-200" />

      <EmailTemplatesCard slug={slug} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Email config form
// ---------------------------------------------------------------------------

function EmailConfigCard({
  tenantId,
  email,
  canManage,
}: {
  tenantId: string;
  email: TenantEmailResponse;
  canManage: boolean;
}) {
  const qc = useQueryClient();
  const [fromAddress, setFromAddress] = useState(email.fromAddressOverride ?? '');
  const [fromDisplayName, setFromDisplayName] = useState(email.fromDisplayNameOverride ?? '');
  const [replyToAddress, setReplyToAddress] = useState(email.replyToAddress ?? '');

  // If the GET resolves after the form mounts, reset to its values once.
  useEffect(() => {
    setFromAddress(email.fromAddressOverride ?? '');
    setFromDisplayName(email.fromDisplayNameOverride ?? '');
    setReplyToAddress(email.replyToAddress ?? '');
  }, [email.fromAddressOverride, email.fromDisplayNameOverride, email.replyToAddress]);

  const dirty = useMemo(() => {
    return (fromAddress ?? '') !== (email.fromAddressOverride ?? '')
      || (fromDisplayName ?? '') !== (email.fromDisplayNameOverride ?? '')
      || (replyToAddress ?? '') !== (email.replyToAddress ?? '');
  }, [fromAddress, fromDisplayName, replyToAddress, email]);

  const save = useMutation({
    mutationFn: () => api.updateTenantEmail(tenantId, {
      fromAddress: fromAddress.trim() === '' ? null : fromAddress.trim(),
      fromDisplayName: fromDisplayName.trim() === '' ? null : fromDisplayName.trim(),
      replyToAddress: replyToAddress.trim() === '' ? null : replyToAddress.trim(),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tenant-email', tenantId] });
    },
  });

  return (
    <div className="bg-white border rounded p-4 space-y-4">
      <div className="flex items-center gap-2">
        <DomainAuthBadge status={email.domainAuthStatus} />
        <span className="text-xs text-slate-500">
          Active From: <code className="font-mono">{email.fromAddress}</code>
        </span>
      </div>

      <div className="space-y-3">
        <FormRow
          label="From address"
          helper="Defaults to noreply@mcp-mesh.io if blank. Must match a domain you've authenticated below (unless using the platform fallback)."
        >
          <input
            type="email"
            value={fromAddress}
            onChange={(e) => setFromAddress(e.target.value)}
            placeholder={email.fromAddress}
            disabled={!canManage || save.isPending}
            className="w-full border rounded px-2 py-1 text-sm font-mono disabled:bg-slate-50"
          />
        </FormRow>

        <FormRow
          label="From display name"
          helper="Shown in the user's inbox alongside the From address. Defaults to tenant display name if blank."
        >
          <input
            value={fromDisplayName}
            onChange={(e) => setFromDisplayName(e.target.value)}
            placeholder={email.fromDisplayName}
            disabled={!canManage || save.isPending}
            className="w-full border rounded px-2 py-1 text-sm disabled:bg-slate-50"
          />
        </FormRow>

        <FormRow
          label="Reply-To address (optional)"
          helper="Where user replies go. Blank means KC defaults to the From address."
        >
          <input
            type="email"
            value={replyToAddress}
            onChange={(e) => setReplyToAddress(e.target.value)}
            placeholder=""
            disabled={!canManage || save.isPending}
            className="w-full border rounded px-2 py-1 text-sm font-mono disabled:bg-slate-50"
          />
        </FormRow>
      </div>

      {save.isError && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-xs text-red-900">
          {updateErrorMessage(save.error)}
        </div>
      )}

      {canManage && (
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => save.mutate()}
            disabled={!dirty || save.isPending}
            className="bg-slate-900 text-white px-3 py-1.5 rounded text-sm hover:bg-slate-700 disabled:opacity-50"
          >
            {save.isPending ? 'Saving…' : 'Save'}
          </button>
          {dirty && (
            <button
              type="button"
              onClick={() => {
                setFromAddress(email.fromAddressOverride ?? '');
                setFromDisplayName(email.fromDisplayNameOverride ?? '');
                setReplyToAddress(email.replyToAddress ?? '');
              }}
              className="text-sm text-slate-600 hover:text-slate-900 px-3 py-1.5"
            >
              Revert
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Domain authentication card
// ---------------------------------------------------------------------------

function DomainAuthCard({
  tenantId,
  email,
  domainAuth,
  canManage,
  onRefresh,
}: {
  tenantId: string;
  email: TenantEmailResponse;
  domainAuth: DomainAuthResponse;
  canManage: boolean;
  onRefresh: () => void;
}) {
  const toast = useToast();
  const defaultDomain = domainAuth.domain
    ?? extractDomain(email.fromAddressOverride ?? email.fromAddress)
    ?? '';
  const [domainInput, setDomainInput] = useState(defaultDomain);

  useEffect(() => {
    setDomainInput(defaultDomain);
  }, [defaultDomain]);

  // ---- auto-validation after a DKIM CNAME push (#103) ----------------------
  // When the push succeeds but SendGrid hasn't validated yet, wait ~30s for
  // DNS to settle, then poll revalidate a few times (mirrors the wizard's
  // domain-auth poll loop). The manual Re-verify button keeps working
  // throughout. Timers are cleaned up on unmount.
  const [autoValidating, setAutoValidating] = useState(false);
  const cancelledRef = useRef(false);
  const timersRef = useRef<number[]>([]);

  useEffect(() => () => {
    cancelledRef.current = true;
    timersRef.current.forEach(t => window.clearTimeout(t));
  }, []);

  function sleep(ms: number): Promise<void> {
    return new Promise(resolve => {
      timersRef.current.push(window.setTimeout(resolve, ms));
    });
  }

  function scheduleAutoValidate() {
    setAutoValidating(true);
    void (async () => {
      await sleep(30_000);
      for (let attempt = 0; attempt < 4 && !cancelledRef.current; attempt++) {
        try {
          const resp = await api.revalidateDomainAuth(tenantId);
          onRefresh();
          if (resp.valid === true) {
            if (!cancelledRef.current) toast.success('Email domain validated');
            break;
          }
        } catch {
          break; // transient revalidate error — stop polling, manual Re-verify remains
        }
        if (attempt < 3) await sleep(15_000);
      }
      if (!cancelledRef.current) setAutoValidating(false);
    })();
  }

  const start = useMutation({
    mutationFn: (d: string) => api.startDomainAuth(tenantId, d),
    onSuccess: (resp) => {
      onRefresh();
      // CNAMEs pushed to CF but not yet validated → auto-validate shortly.
      if (resp.valid !== true && resp.zoneInOurAccount && resp.cnames.length > 0) {
        scheduleAutoValidate();
      }
    },
  });

  const revalidate = useMutation({
    mutationFn: () => api.revalidateDomainAuth(tenantId),
    onSuccess: () => onRefresh(),
  });

  const showManualCnames =
    domainAuth.cnames.length > 0
    && !domainAuth.zoneInOurAccount
    && domainAuth.valid !== true;

  return (
    <div className="bg-white border rounded p-4 space-y-4">
      <div className="flex items-end gap-3">
        <FormRow label="Domain to authenticate" helper="e.g. example.com (the registrable parent of your From address)">
          <input
            value={domainInput}
            onChange={(e) => setDomainInput(e.target.value)}
            placeholder="example.com"
            disabled={!canManage || start.isPending || revalidate.isPending}
            className="w-full border rounded px-2 py-1 text-sm font-mono disabled:bg-slate-50"
          />
        </FormRow>
      </div>

      {canManage && (
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => start.mutate(domainInput.trim())}
            disabled={!domainInput.trim() || start.isPending || revalidate.isPending}
            className="bg-slate-900 text-white px-3 py-1.5 rounded text-sm hover:bg-slate-700 disabled:opacity-50"
          >
            {start.isPending ? 'Authenticating…' : 'Authenticate domain'}
          </button>
          {domainAuth.sendgridDomainId && (
            <button
              type="button"
              onClick={() => revalidate.mutate()}
              disabled={start.isPending || revalidate.isPending}
              className="bg-white border px-3 py-1.5 rounded text-sm hover:bg-slate-50 disabled:opacity-50"
            >
              {revalidate.isPending ? 'Re-verifying…' : 'Re-verify'}
            </button>
          )}
        </div>
      )}

      {autoValidating && domainAuth.valid !== true && (
        <div className="flex items-center gap-2 text-xs text-slate-600">
          <span
            className="inline-block w-3.5 h-3.5 border-2 border-slate-400 border-t-transparent rounded-full animate-spin"
            aria-hidden
          />
          Validating… DKIM CNAMEs pushed; re-checking with SendGrid automatically
          (usually completes within a minute).
        </div>
      )}

      {start.isError && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-xs text-red-900">
          {String(start.error)}
        </div>
      )}
      {revalidate.isError && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-xs text-red-900">
          {String(revalidate.error)}
        </div>
      )}

      {showManualCnames && (
        <ManualCnamesBlock cnames={domainAuth.cnames} />
      )}

      {domainAuth.cnames.length > 0 && domainAuth.zoneInOurAccount && (
        <CnamesPushedBlock cnames={domainAuth.cnames} valid={domainAuth.valid === true} />
      )}
    </div>
  );
}

function ManualCnamesBlock({ cnames }: { cnames: DomainAuthCname[] }) {
  function copyAll() {
    const text = cnames.map(c => `${c.host}\tCNAME\t${c.target}`).join('\n');
    navigator.clipboard.writeText(text).catch(() => { /* clipboard blocked */ });
  }
  return (
    <div className="bg-amber-50 border border-amber-200 rounded p-3 space-y-2">
      <div className="text-sm text-amber-900">
        Cloudflare zone not in our CF account — add these 3 CNAME records manually
        at your DNS provider, then click <span className="font-semibold">Re-verify</span>.
      </div>
      <pre className="bg-white border border-amber-200 rounded p-2 text-xs font-mono overflow-x-auto">
        {cnames.map(c => `${c.host}\tCNAME\t${c.target}`).join('\n')}
      </pre>
      <button
        type="button"
        onClick={copyAll}
        className="bg-amber-900 text-white px-2 py-1 rounded text-xs hover:bg-amber-700"
      >
        Copy block
      </button>
    </div>
  );
}

function CnamesPushedBlock({ cnames, valid }: { cnames: DomainAuthCname[]; valid: boolean }) {
  return (
    <div className={'border rounded p-3 ' + (valid ? 'bg-emerald-50 border-emerald-200' : 'bg-slate-50 border-slate-200')}>
      <div className="text-sm text-slate-700 mb-2">
        {valid
          ? 'All 3 CNAMEs published and validated by SendGrid.'
          : 'CNAMEs published to Cloudflare. SendGrid validation may take a few minutes; click Re-verify after.'}
      </div>
      <ul className="text-xs font-mono space-y-0.5">
        {cnames.map(c => (
          <li key={c.host} className={c.pushed ? '' : 'text-amber-700'}>
            {c.pushed ? '✓ ' : '⚠ '}{c.host} → {c.target}
            {c.pushError && <span className="text-red-700 ml-2">({c.pushError})</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Send rate limits (per-tenant overrides on the send-API limiter)
// ---------------------------------------------------------------------------

const RATE_LIMIT_MAX = 100_000;

/** Blank = clear (platform default); otherwise a positive int ≤ 100000. */
function parseRateLimitInput(raw: string): { ok: boolean; value: number | null } {
  const trimmed = raw.trim();
  if (trimmed === '') return { ok: true, value: null };
  if (!/^\d+$/.test(trimmed)) return { ok: false, value: null };
  const n = Number(trimmed);
  if (!Number.isInteger(n) || n < 1 || n > RATE_LIMIT_MAX) return { ok: false, value: null };
  return { ok: true, value: n };
}

function RateLimitsCard({
  tenantId, canManage,
}: {
  tenantId: string;
  canManage: boolean;
}) {
  const qc = useQueryClient();
  const toast = useToast();
  const rl = useQuery({
    queryKey: ['tenant-email-rate-limit', tenantId],
    queryFn: () => api.getEmailRateLimit(tenantId),
    enabled: !!tenantId,
  });

  const [editing, setEditing] = useState(false);
  const [perMinuteInput, setPerMinuteInput] = useState('');
  const [perDayInput, setPerDayInput] = useState('');

  const perMinuteParsed = parseRateLimitInput(perMinuteInput);
  const perDayParsed = parseRateLimitInput(perDayInput);

  const save = useMutation({
    // ALWAYS send both fields: null clears that override server-side, so an
    // omitted field would silently wipe the other override.
    mutationFn: () => api.updateEmailRateLimit(tenantId, {
      perMinute: perMinuteParsed.value,
      perDay: perDayParsed.value,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tenant-email-rate-limit', tenantId] });
      toast.success('Send rate limits saved');
      setEditing(false);
    },
    onError: (err) => toast.error(updateErrorMessage(err)),
  });

  if (rl.isLoading) return <div>Loading…</div>;
  if (rl.isError) {
    return (
      <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
        {String(rl.error)}
      </div>
    );
  }
  if (!rl.data) return null;
  const data = rl.data;

  function openEditor() {
    setPerMinuteInput(data.perMinuteOverride !== null ? String(data.perMinuteOverride) : '');
    setPerDayInput(data.perDayOverride !== null ? String(data.perDayOverride) : '');
    setEditing(true);
  }

  return (
    <div className="bg-white border rounded p-4 space-y-3">
      {!data.enabled && (
        <div className="bg-slate-50 border border-slate-200 rounded p-2 text-xs text-slate-600">
          Rate limiting is currently disabled platform-wide; these limits are
          not being enforced.
        </div>
      )}

      <dl className="grid grid-cols-[140px_1fr] gap-y-1 text-sm items-center">
        <dt className="text-slate-500">Per minute</dt>
        <dd>
          <span className="font-mono">{data.perMinute}</span>
          <RateLimitProvenance override={data.perMinuteOverride} platform={data.platformPerMinute} />
        </dd>
        <dt className="text-slate-500">Per day</dt>
        <dd>
          <span className="font-mono">{data.perDay}</span>
          <RateLimitProvenance override={data.perDayOverride} platform={data.platformPerDay} />
        </dd>
      </dl>

      {canManage && !editing && (
        <button
          type="button"
          onClick={openEditor}
          className="bg-white border px-3 py-1.5 rounded text-sm hover:bg-slate-50"
        >
          Edit overrides
        </button>
      )}

      {canManage && editing && (
        <div className="border-t pt-3 space-y-3">
          <div className="grid grid-cols-2 gap-3 max-w-md">
            <FormRow
              label="Per-minute override"
              helper={`Blank = platform default (${data.platformPerMinute})`}
            >
              <input
                value={perMinuteInput}
                onChange={(e) => setPerMinuteInput(e.target.value)}
                placeholder={String(data.platformPerMinute)}
                disabled={save.isPending}
                className="w-full border rounded px-2 py-1 text-sm font-mono disabled:bg-slate-50"
              />
              {!perMinuteParsed.ok && (
                <div className="text-red-700 text-xs">
                  Must be a positive integer ≤ {RATE_LIMIT_MAX.toLocaleString()}
                </div>
              )}
            </FormRow>
            <FormRow
              label="Per-day override"
              helper={`Blank = platform default (${data.platformPerDay})`}
            >
              <input
                value={perDayInput}
                onChange={(e) => setPerDayInput(e.target.value)}
                placeholder={String(data.platformPerDay)}
                disabled={save.isPending}
                className="w-full border rounded px-2 py-1 text-sm font-mono disabled:bg-slate-50"
              />
              {!perDayParsed.ok && (
                <div className="text-red-700 text-xs">
                  Must be a positive integer ≤ {RATE_LIMIT_MAX.toLocaleString()}
                </div>
              )}
            </FormRow>
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => save.mutate()}
              disabled={save.isPending || !perMinuteParsed.ok || !perDayParsed.ok}
              className="bg-slate-900 text-white px-3 py-1.5 rounded text-sm hover:bg-slate-700 disabled:opacity-50"
            >
              {save.isPending ? 'Saving…' : 'Save'}
            </button>
            <button
              type="button"
              onClick={() => setEditing(false)}
              disabled={save.isPending}
              className="text-sm text-slate-600 hover:text-slate-900 px-3 py-1.5"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function RateLimitProvenance({
  override, platform,
}: {
  override: number | null;
  platform: number;
}) {
  return override !== null ? (
    <span
      className="ml-2 text-xs px-2 py-0.5 rounded border bg-blue-50 text-blue-800 border-blue-200"
      title={`Platform default: ${platform}`}
    >
      override
    </span>
  ) : (
    <span className="ml-2 text-xs px-2 py-0.5 rounded border bg-slate-100 text-slate-600 border-slate-200">
      platform default
    </span>
  );
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function FormRow({
  label, helper, children,
}: {
  label: string;
  helper?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block space-y-1">
      <div className="text-xs text-slate-600">{label}</div>
      {children}
      {helper && <div className="text-xs text-slate-500">{helper}</div>}
    </label>
  );
}

function DomainAuthBadge({ status }: { status: DomainAuthStatus }) {
  const label =
    status === 'VALID' ? 'Authenticated ✓' :
    status === 'PENDING' ? 'Pending ⏳' :
    status === 'FAILED' ? 'Failed ✗' :
    'Not started';
  const cls =
    status === 'VALID' ? 'bg-emerald-100 text-emerald-800 border-emerald-200' :
    status === 'PENDING' ? 'bg-amber-100 text-amber-800 border-amber-200' :
    status === 'FAILED' ? 'bg-red-100 text-red-800 border-red-200' :
    'bg-slate-100 text-slate-700 border-slate-200';
  return (
    <span className={'text-xs px-2 py-0.5 rounded border ' + cls}>
      {label}
    </span>
  );
}

function extractDomain(email: string | null): string | null {
  if (!email) return null;
  const at = email.lastIndexOf('@');
  if (at < 0 || at === email.length - 1) return null;
  return email.substring(at + 1).toLowerCase();
}

function updateErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    const body = err.body as { message?: string } | string | null;
    if (typeof body === 'object' && body && 'message' in body && typeof body.message === 'string') {
      return body.message;
    }
    if (err.status === 400) {
      // Surface the canonical email.* error codes our backend emits.
      const m = err.message.match(/(email\.[a-z_]+):\s*(.+?)("|$)/);
      if (m) return m[2];
    }
  }
  return String(err);
}
