import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import type { Tenant, IdentityProviderDto } from '../api/types';

const DRAFT_STORAGE_KEY = 'mcpmesh.tenantwizard.draft.v1';

// File objects can't be JSON-serialized — exclude them from persisted draft.
type PersistedDraft = {
  step: 1 | 2 | 3 | 4 | 5;
  maxStepReached: 1 | 2 | 3 | 4 | 5;
  basics: WizardBasics;
  apps: WizardApp[];
  // manifestFile + themeFile are deliberately NOT persisted; on restore the
  // operator must re-pick those files. We track this with restoredFromDraft.
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type AppProfile = 'CONFIDENTIAL_BACKEND' | 'SPA_PKCE' | 'SERVICE_ACCOUNT_ONLY';

interface WizardHostname { host: string; backend: string; }

interface WizardApp {
  slug: string;
  displayName: string;
  profile: AppProfile;
  audience: string[];
  saPermissions: string[];
  /** Sentinel: true for apps loaded via resume-mode (already provisioned). */
  _existing?: boolean;
}

interface WizardBasics {
  slug: string;
  displayName: string;
  adminEmail: string;
  hostnames: WizardHostname[];
}

type ProgressStatus = 'pending' | 'in_progress' | 'success' | 'error';

interface ProgressRow {
  key: string;
  label: string;
  status: ProgressStatus;
  detail?: string;
}

interface CreatedAppInfo {
  slug: string;
  displayName: string;
  appId: string;
  clientId: string;
  clientSecret: string | null;
  profile: AppProfile;
}

const APP_PROFILE_LABELS: Record<AppProfile, string> = {
  CONFIDENTIAL_BACKEND: 'Confidential backend',
  SPA_PKCE: 'SPA (PKCE)',
  SERVICE_ACCOUNT_ONLY: 'Service account only',
};

const SA_PERMISSION_PRESET = ['USER_LIST', 'USER_INVITE', 'USER_DISABLE', 'AUDIT_VIEW'];

const SLUG_PATTERN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function TenantWizard() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const resumeId = searchParams.get('resume');
  const [step, setStep] = useState<1 | 2 | 3 | 4 | 5>(1);
  const [maxStepReached, setMaxStepReached] = useState<1 | 2 | 3 | 4 | 5>(1);

  const [basics, setBasics] = useState<WizardBasics>({
    slug: '',
    displayName: '',
    adminEmail: '',
    hostnames: [{ host: '', backend: '' }],
  });
  const [apps, setApps] = useState<WizardApp[]>([]);
  const [manifestFile, setManifestFile] = useState<File | undefined>(undefined);
  const [themeFile, setThemeFile] = useState<File | undefined>(undefined);

  // Generate-phase state
  const [generating, setGenerating] = useState(false);
  const [progress, setProgress] = useState<ProgressRow[]>([]);
  const [createdTenant, setCreatedTenant] = useState<Tenant | null>(null);
  const [createdApps, setCreatedApps] = useState<CreatedAppInfo[]>([]);
  const [finished, setFinished] = useState(false);
  const [revealedSecrets, setRevealedSecrets] = useState<Set<string>>(new Set());

  // ---- resume mode (prefill from existing non-ACTIVE tenant) --------------
  // Operator clicks "Resume" on a non-ACTIVE tenant from the Tenants list.
  // Takes precedence over draft restoration — if you're resuming, throw away
  // the unrelated draft you might have had.
  const [resumedFromTenant, setResumedFromTenant] = useState<Tenant | null>(null);
  const resumeHydratedRef = useRef(false);

  useEffect(() => {
    if (!resumeId || resumeHydratedRef.current) return;
    resumeHydratedRef.current = true;
    (async () => {
      try {
        const tenant = await api.getTenant(resumeId);
        const existingApps = await api.listApps(tenant.id);
        // Filter out the platform-managed 'usermanagement' app — it's not a
        // tenant-app and shouldn't appear in the wizard's Apps step.
        const userApps = existingApps.filter(a => a.slug !== 'usermanagement');
        setBasics({
          slug:         tenant.slug,
          displayName:  tenant.displayName,
          adminEmail:   '',
          hostnames:    tenant.hostnames ?? [],
        });
        // For resume mode, treat existing apps as "already provisioned" — show
        // them in step 2 with a small badge so the operator can ADD MORE apps
        // but not edit/delete the existing rows from inside the wizard. (App
        // editing/deletion stays in the Apps tab on tenant detail.)
        setApps(userApps.map(a => ({
          slug: a.slug,
          displayName: a.displayName,
          profile: 'CONFIDENTIAL_BACKEND' as AppProfile,
          audience: [],
          saPermissions: [],
          _existing: true,
        })));
        setMaxStepReached(1);
        setStep(1);
        setResumedFromTenant(tenant);
      } catch (e: any) {
        console.warn('Resume mode: failed to load tenant', resumeId, e);
      }
    })();
  }, [resumeId]);

  // ---- draft persistence (sessionStorage) ---------------------------------
  // Survives the 401 → BFF sign-in → redirect_back round-trip so the operator's
  // in-progress input is not lost when the session expires mid-wizard.
  const [restoredFromDraft, setRestoredFromDraft] = useState(false);
  const draftHydrated = useRef(false);

  useEffect(() => {
    const raw = sessionStorage.getItem(DRAFT_STORAGE_KEY);
    draftHydrated.current = true;
    // Resume mode takes precedence — don't restore unrelated draft.
    if (resumeId) return;
    if (!raw) return;
    try {
      const draft = JSON.parse(raw) as PersistedDraft;
      if (draft.step !== undefined) setStep(draft.step);
      if (draft.maxStepReached !== undefined) setMaxStepReached(draft.maxStepReached);
      if (draft.basics) setBasics(draft.basics);
      if (draft.apps) setApps(draft.apps);
      setRestoredFromDraft(true);
    } catch {
      sessionStorage.removeItem(DRAFT_STORAGE_KEY);
    }
  }, []);

  useEffect(() => {
    // Skip the very first render (before hydration completes) so we don't
    // overwrite a stored draft with the initial empty state.
    if (!draftHydrated.current) return;
    const draft: PersistedDraft = { step, maxStepReached, basics, apps };
    sessionStorage.setItem(DRAFT_STORAGE_KEY, JSON.stringify(draft));
  }, [step, maxStepReached, basics, apps]);

  const clearDraft = () => sessionStorage.removeItem(DRAFT_STORAGE_KEY);

  // ---- validation per step --------------------------------------------------

  const basicsValid = useMemo(() => {
    if (!SLUG_PATTERN.test(basics.slug)) return false;
    if (!basics.displayName.trim()) return false;
    if (!EMAIL_PATTERN.test(basics.adminEmail)) return false;
    if (basics.hostnames.length < 1) return false;
    if (!basics.hostnames.every(h => h.host.trim().length > 0)) return false;
    return true;
  }, [basics]);

  const appsValid = useMemo(() => {
    const seen = new Set<string>();
    for (const a of apps) {
      if (!SLUG_PATTERN.test(a.slug)) return false;
      if (!a.displayName.trim()) return false;
      if (seen.has(a.slug)) return false;
      seen.add(a.slug);
    }
    return true;
  }, [apps]);

  function gotoStep(target: 1 | 2 | 3 | 4 | 5) {
    setStep(target);
    if (target > maxStepReached) setMaxStepReached(target);
  }

  // ---- step navigation ------------------------------------------------------

  function next() {
    if (step === 1 && !basicsValid) return;
    if (step === 2 && !appsValid) return;
    const target = (step + 1) as 1 | 2 | 3 | 4 | 5;
    gotoStep(target);
  }

  function back() {
    if (step === 1) return;
    const target = (step - 1) as 1 | 2 | 3 | 4 | 5;
    setStep(target);
  }

  // ---- generate flow --------------------------------------------------------

  async function runStep(
    rows: ProgressRow[],
    setRows: (next: ProgressRow[]) => void,
    key: string,
    fn: () => Promise<void>
  ): Promise<boolean> {
    let updated = rows.map(r => r.key === key ? { ...r, status: 'in_progress' as ProgressStatus } : r);
    setRows(updated);
    try {
      await fn();
      updated = updated.map(r => r.key === key ? { ...r, status: 'success' as ProgressStatus } : r);
      setRows(updated);
      // mutate the local `rows` array too so subsequent calls within the
      // same generate pass see the latest state without a render cycle.
      rows.length = 0;
      rows.push(...updated);
      return true;
    } catch (e) {
      const detail = e instanceof ApiError ? e.message : String(e);
      updated = updated.map(r => r.key === key ? { ...r, status: 'error' as ProgressStatus, detail } : r);
      setRows(updated);
      rows.length = 0;
      rows.push(...updated);
      return false;
    }
  }

  // Tenant DB status can be ACTIVE even if UsermanagementBootstrap failed
  // partway (the bootstrap exception bubbles up to the controller but the
  // tenant row is already committed). Detect this by checking whether the
  // realm's "usermanagement" client got created.
  async function needsRetry(tenantId: string): Promise<boolean> {
    try {
      const list = await api.listApps(tenantId);
      return !list.some(a => a.slug === 'usermanagement');
    } catch {
      return false;
    }
  }

  async function generate() {
    setGenerating(true);
    setFinished(false);

    // Pre-seed the progress rows so the operator sees the full plan up-front.
    const rows: ProgressRow[] = [
      { key: 'tenant', label: `Create tenant '${basics.slug}'`, status: 'pending' },
    ];
    for (const a of apps) {
      rows.push({ key: `app:${a.slug}`, label: `Create app '${a.slug}'`, status: 'pending' });
    }
    for (const a of apps) {
      if (a.saPermissions.length > 0) {
        rows.push({
          key: `sa:${a.slug}`,
          label: `Grant SA perms to '${a.slug}' (${a.saPermissions.join(', ')})`,
          status: 'pending',
        });
      }
    }
    if (manifestFile) rows.push({ key: 'manifest', label: `Apply manifest (${manifestFile.name})`, status: 'pending' });
    if (themeFile) rows.push({ key: 'theme', label: `Upload theme (${themeFile.name})`, status: 'pending' });
    setProgress([...rows]);

    // ---- 1. Tenant ----------------------------------------------------------
    // Idempotent create: if createTenant errors (409 duplicate, or 500 after a
    // partial bootstrap), try to fetch by slug — if it exists, we're recovering
    // from a prior half-completed run; otherwise surface the original error.
    let tenant: Tenant | null = null;
    {
      const key = 'tenant';
      let updated = rows.map(r => r.key === key ? { ...r, status: 'in_progress' as ProgressStatus } : r);
      setProgress(updated);
      rows.length = 0; rows.push(...updated);
      try {
        tenant = await api.createTenant({
          slug: basics.slug,
          displayName: basics.displayName,
          adminEmail: basics.adminEmail,
          hostnames: basics.hostnames.map(h => ({
            host: h.host.trim(),
            backend: (h.backend.trim() || `${h.host.trim()}:80`),
          })),
        });
        updated = updated.map(r => r.key === key ? { ...r, status: 'success' as ProgressStatus, detail: `Created '${tenant!.slug}'` } : r);
        setProgress(updated);
        rows.length = 0; rows.push(...updated);
      } catch (e) {
        let existing: Tenant | null = null;
        try {
          existing = await api.getTenantBySlug(basics.slug);
        } catch {
          const detail = e instanceof ApiError ? e.message : String(e);
          updated = updated.map(r => r.key === key ? { ...r, status: 'error' as ProgressStatus, detail } : r);
          setProgress(updated);
          rows.length = 0; rows.push(...updated);
          setGenerating(false);
          return;
        }
        tenant = existing;
        updated = updated.map(r => r.key === key ? {
          ...r,
          status: 'success' as ProgressStatus,
          detail: `Tenant '${existing!.slug}' already exists (status=${existing!.status}); resuming`,
        } : r);
        setProgress(updated);
        rows.length = 0; rows.push(...updated);
      }
    }
    if (!tenant) { setGenerating(false); return; }
    setCreatedTenant(tenant);

    // Retry bootstrap if the tenant row is FAILED or if the usermanagement
    // client never got created (bootstrap exception bubbled up but the tenant
    // row was already committed).
    const shouldRetry = tenant.status === 'FAILED' || (await needsRetry(tenant.id));
    if (shouldRetry) {
      const key = 'retry';
      const retryRow: ProgressRow = { key, label: 'Retry bootstrap', status: 'in_progress' };
      let updated = [...rows, retryRow];
      setProgress(updated);
      rows.length = 0; rows.push(...updated);
      try {
        tenant = await api.retryTenant(tenant.id);
        updated = updated.map(r => r.key === key ? {
          ...r,
          status: 'success' as ProgressStatus,
          detail: `Re-bootstrapped to status=${tenant!.status}`,
        } : r);
        setProgress(updated);
        rows.length = 0; rows.push(...updated);
        setCreatedTenant(tenant);
      } catch (e) {
        const detail = e instanceof ApiError ? e.message : String(e);
        updated = updated.map(r => r.key === key ? { ...r, status: 'error' as ProgressStatus, detail } : r);
        setProgress(updated);
        rows.length = 0; rows.push(...updated);
        setGenerating(false);
        return;
      }
    }

    // ---- 2. Apps (sequential — audience targets must exist first) ----------
    // Idempotent create: if createApp 409s, fall back to listApps and reuse
    // the existing record. clientSecret is one-shot at create time, so for
    // pre-existing apps we record null and surface a hint to the operator.
    const created: CreatedAppInfo[] = [];
    for (const app of apps) {
      const key = `app:${app.slug}`;
      let updated = rows.map(r => r.key === key ? { ...r, status: 'in_progress' as ProgressStatus } : r);
      setProgress(updated);
      rows.length = 0; rows.push(...updated);
      try {
        const result = await api.createApp(tenant!.id, {
          slug: app.slug,
          displayName: app.displayName,
          profile: app.profile,
          audience: app.audience,
        });
        created.push({
          slug: app.slug,
          displayName: app.displayName,
          appId: result.id,
          clientId: result.clientId,
          clientSecret: result.clientSecret ?? null,
          profile: app.profile,
        });
        setCreatedApps([...created]);
        updated = updated.map(r => r.key === key ? { ...r, status: 'success' as ProgressStatus } : r);
        setProgress(updated);
        rows.length = 0; rows.push(...updated);
      } catch (e) {
        const all = await api.listApps(tenant!.id).catch(() => [] as import('../api/types').App[]);
        const existing = all.find(a => a.slug === app.slug);
        if (existing) {
          created.push({
            slug: app.slug,
            displayName: app.displayName,
            appId: existing.id,
            clientId: existing.clientId,
            clientSecret: null,
            profile: app.profile,
          });
          setCreatedApps([...created]);
          updated = updated.map(r => r.key === key ? {
            ...r,
            status: 'success' as ProgressStatus,
            detail: 'Already existed; clientSecret captured previously (re-create to reset)',
          } : r);
          setProgress(updated);
          rows.length = 0; rows.push(...updated);
        } else {
          const detail = e instanceof ApiError ? e.message : String(e);
          updated = updated.map(r => r.key === key ? { ...r, status: 'error' as ProgressStatus, detail } : r);
          setProgress(updated);
          rows.length = 0; rows.push(...updated);
          setGenerating(false);
          return;
        }
      }
    }

    // ---- 3. SA perms --------------------------------------------------------
    for (const app of apps) {
      if (app.saPermissions.length === 0) continue;
      const ok = await runStep(rows, setProgress, `sa:${app.slug}`, async () => {
        const c = created.find(x => x.slug === app.slug);
        if (!c) throw new Error(`internal: missing created app for slug ${app.slug}`);
        await api.updateServiceAccountPermissions(tenant!.id, c.appId, app.saPermissions);
      });
      if (!ok) { setGenerating(false); return; }
    }

    // ---- 4. Manifest --------------------------------------------------------
    if (manifestFile) {
      const ok = await runStep(rows, setProgress, 'manifest', async () => {
        const text = await manifestFile.text();
        await api.uploadManifest(tenant!.id, text);
      });
      if (!ok) { setGenerating(false); return; }
    }

    // ---- 5. Theme -----------------------------------------------------------
    if (themeFile) {
      const ok = await runStep(rows, setProgress, 'theme', async () => {
        await api.uploadTheme(basics.slug, themeFile);
      });
      if (!ok) { setGenerating(false); return; }
    }

    setGenerating(false);
    setFinished(true);
    clearDraft();
  }

  function resetWizard() {
    setStep(1);
    setMaxStepReached(1);
    setBasics({ slug: '', displayName: '', adminEmail: '', hostnames: [{ host: '', backend: '' }] });
    setApps([]);
    setManifestFile(undefined);
    setThemeFile(undefined);
    setProgress([]);
    setCreatedTenant(null);
    setCreatedApps([]);
    setFinished(false);
    setGenerating(false);
    setRevealedSecrets(new Set());
  }

  // ---------------------------------------------------------------------------
  // Render: success page short-circuits the wizard chrome.
  // ---------------------------------------------------------------------------

  if (finished && createdTenant) {
    return (
      <SuccessPage
        tenant={createdTenant}
        apps={createdApps}
        revealedSecrets={revealedSecrets}
        onReveal={(clientId, secret) => {
          setRevealedSecrets(prev => {
            const next = new Set(prev);
            next.add(clientId);
            return next;
          });
          if (secret) navigator.clipboard.writeText(secret).catch(() => { /* clipboard blocked */ });
        }}
        onViewTenant={() => navigate(`/tenants/${createdTenant.id}`)}
        onOnboardAnother={resetWizard}
      />
    );
  }

  // ---- generate-in-progress overlay sits below the (now disabled) review --

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Link to="/tenants" className="text-slate-500 hover:text-slate-900">← Tenants</Link>
        <h1 className="text-2xl font-semibold">Onboard new tenant</h1>
      </div>

      <StepProgress
        current={step}
        maxReached={maxStepReached}
        onJump={(s) => { if (s <= maxStepReached && !generating) setStep(s); }}
      />

      {resumedFromTenant && (
        <div className="mb-3 px-3 py-2 bg-blue-50 border border-blue-200 rounded text-xs">
          <span className="font-medium">Resuming onboarding</span> for{' '}
          <code className="font-mono">{resumedFromTenant.slug}</code> (status:{' '}
          <code className="font-mono">{resumedFromTenant.status}</code>). Basics
          locked; add or edit apps below + click Generate to retry bootstrap + finish.
        </div>
      )}

      {restoredFromDraft && !resumedFromTenant && (
        <div className="px-3 py-2 bg-amber-50 border border-amber-200 rounded text-xs flex justify-between items-center">
          <span className="text-amber-900">
            Restored your in-progress draft. Files (manifest / theme) need to be re-selected if you uploaded any.
          </span>
          <button
            type="button"
            onClick={() => {
              clearDraft();
              window.location.reload();
            }}
            className="text-amber-900 underline ml-3 whitespace-nowrap"
          >
            Discard draft + start fresh
          </button>
        </div>
      )}

      {step === 1 && (
        <Step1Basics basics={basics} onChange={setBasics} />
      )}
      {step === 2 && (
        <Step2Apps apps={apps} onChange={setApps} />
      )}
      {step === 3 && (
        <Step3Manifest file={manifestFile} onChange={setManifestFile} />
      )}
      {step === 4 && (
        <Step4Theme file={themeFile} onChange={setThemeFile} />
      )}
      {step === 5 && (
        <Step5Review
          basics={basics}
          apps={apps}
          manifestFile={manifestFile}
          themeFile={themeFile}
        />
      )}

      {generating || progress.length > 0 ? (
        <GenerateProgressPanel rows={progress} />
      ) : null}

      <div className="flex justify-between items-center pt-2">
        <div>
          {step > 1 && (
            <button onClick={back} disabled={generating}
                    className="text-sm text-slate-600 hover:text-slate-900 disabled:opacity-50">
              ← Back
            </button>
          )}
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => { clearDraft(); navigate('/tenants'); }}
            className="text-sm text-slate-600 hover:text-slate-900 px-3 py-1.5"
          >
            Cancel
          </button>
          {step < 5 && (
            <button
              onClick={next}
              disabled={(step === 1 && !basicsValid) || (step === 2 && !appsValid)}
              className="bg-slate-900 text-white px-3 py-1.5 rounded text-sm hover:bg-slate-700 disabled:opacity-50"
            >
              Next →
            </button>
          )}
          {step === 5 && (
            <button
              onClick={generate}
              disabled={generating || !basicsValid || !appsValid}
              className="bg-emerald-700 text-white px-3 py-1.5 rounded text-sm hover:bg-emerald-800 disabled:opacity-50"
            >
              {generating ? 'Generating…' : 'Generate'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step progress indicator
// ---------------------------------------------------------------------------

const STEP_LABELS = ['Basics', 'Apps', 'Manifest', 'Theme', 'Review'] as const;

function StepProgress({
  current, maxReached, onJump,
}: { current: number; maxReached: number; onJump: (s: 1 | 2 | 3 | 4 | 5) => void }) {
  return (
    <ol className="flex items-center gap-2 text-sm">
      {STEP_LABELS.map((label, i) => {
        const n = (i + 1) as 1 | 2 | 3 | 4 | 5;
        const isCurrent = n === current;
        const isReachable = n <= maxReached;
        return (
          <li key={n} className="flex items-center gap-2">
            <button
              type="button"
              disabled={!isReachable}
              onClick={() => onJump(n)}
              className={
                'flex items-center gap-2 px-2 py-1 rounded ' +
                (isCurrent
                  ? 'bg-slate-900 text-white'
                  : isReachable
                  ? 'text-slate-700 hover:bg-slate-100'
                  : 'text-slate-400 cursor-not-allowed')
              }
            >
              <span className="inline-flex items-center justify-center w-5 h-5 rounded-full border text-xs font-mono">
                {n}
              </span>
              <span>{label}</span>
            </button>
            {n < 5 && <span className="text-slate-300">›</span>}
          </li>
        );
      })}
    </ol>
  );
}

// ---------------------------------------------------------------------------
// Step 1 — Basics
// ---------------------------------------------------------------------------

function Step1Basics({
  basics, onChange,
}: { basics: WizardBasics; onChange: (b: WizardBasics) => void }) {
  const slugBad = basics.slug.length > 0 && !SLUG_PATTERN.test(basics.slug);
  const emailBad = basics.adminEmail.length > 0 && !EMAIL_PATTERN.test(basics.adminEmail);

  return (
    <div className="bg-white border rounded p-6 space-y-5">
      <div className="text-sm text-slate-500">Step 1 of 5 — Basics</div>

      <label className="block">
        <div className="text-xs text-slate-600 mb-1">Slug *</div>
        <div className="flex items-center gap-3">
          <input
            value={basics.slug}
            onChange={(e) => onChange({ ...basics, slug: e.target.value })}
            placeholder="safesound"
            className="w-64 border rounded px-2 py-1 font-mono text-sm"
          />
          <span className="text-xs text-slate-500">
            realm: <code className="font-mono">t-{basics.slug || '<slug>'}</code>
          </span>
        </div>
        <div className="text-xs text-slate-500 mt-1">dns-safe, lowercase, hyphens ok</div>
        {slugBad && (
          <div className="text-red-700 text-xs mt-1">
            Must match <code className="font-mono">^[a-z0-9]([a-z0-9-]*[a-z0-9])?$</code>
          </div>
        )}
      </label>

      <label className="block">
        <div className="text-xs text-slate-600 mb-1">Display name *</div>
        <input
          value={basics.displayName}
          onChange={(e) => onChange({ ...basics, displayName: e.target.value })}
          placeholder="Safe &amp; Sound Home Checkups"
          className="w-full max-w-xl border rounded px-2 py-1 text-sm"
        />
      </label>

      <label className="block">
        <div className="text-xs text-slate-600 mb-1">Admin email *</div>
        <input
          value={basics.adminEmail}
          onChange={(e) => onChange({ ...basics, adminEmail: e.target.value })}
          placeholder="admin@example.com"
          className="w-full max-w-xl border rounded px-2 py-1 text-sm"
        />
        <div className="text-xs text-slate-500 mt-1">
          Gets the tenant-admin role and an invite email.
        </div>
        {emailBad && (
          <div className="text-red-700 text-xs mt-1">Not a valid email address</div>
        )}
      </label>

      <div>
        <div className="text-xs text-slate-600 mb-1">Hostnames *</div>
        <div className="space-y-2">
          {basics.hostnames.map((h, i) => (
            <div key={i} className="flex items-center gap-2">
              <input
                value={h.host}
                onChange={(e) => {
                  const next = [...basics.hostnames];
                  next[i] = { ...next[i], host: e.target.value };
                  onChange({ ...basics, hostnames: next });
                }}
                placeholder="safeandsoundhouses.com"
                className="flex-1 max-w-xl border rounded px-2 py-1 font-mono text-sm"
              />
              <button
                type="button"
                onClick={() => {
                  const next = basics.hostnames.filter((_, j) => j !== i);
                  onChange({
                    ...basics,
                    hostnames: next.length > 0 ? next : [{ host: '', backend: '' }],
                  });
                }}
                className="text-xs text-red-700 hover:underline"
              >
                Remove
              </button>
            </div>
          ))}
        </div>
        <button
          type="button"
          onClick={() => onChange({ ...basics, hostnames: [...basics.hostnames, { host: '', backend: '' }] })}
          className="mt-2 text-sm text-slate-700 hover:text-slate-900"
        >
          + Add hostname
        </button>
        <div className="text-xs text-slate-500 mt-2">
          Backend defaults to <code className="font-mono">&lt;host&gt;:80</code>. For hostnames in our
          CloudFlare account (<code className="font-mono">mcp-mesh.io</code>,{' '}
          <code className="font-mono">safeandsoundhouses.com</code>), the DNS CNAME is
          auto-provisioned at generate time.
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 2 — Apps
// ---------------------------------------------------------------------------

function Step2Apps({
  apps, onChange,
}: { apps: WizardApp[]; onChange: (a: WizardApp[]) => void }) {
  function addApp() {
    onChange([
      ...apps,
      { slug: '', displayName: '', profile: 'CONFIDENTIAL_BACKEND', audience: [], saPermissions: [] },
    ]);
  }

  function patchApp(i: number, patch: Partial<WizardApp>) {
    const next = apps.map((a, j) => (j === i ? { ...a, ...patch } : a));
    onChange(next);
  }

  function removeApp(i: number) {
    onChange(apps.filter((_, j) => j !== i));
  }

  return (
    <div className="space-y-4">
      <div className="bg-white border rounded p-4 text-sm text-slate-600">
        Step 2 of 5 — Apps. You can skip this step if the tenant has no apps yet; apps can be
        added later from the tenant detail page.
      </div>

      {apps.map((app, i) => {
        const otherSlugs = apps.filter((_, j) => j !== i).map(a => a.slug).filter(Boolean);
        const slugBad = app.slug.length > 0 && !SLUG_PATTERN.test(app.slug);
        const dupSlug = app.slug.length > 0 && apps.filter(x => x.slug === app.slug).length > 1;
        const showSa = app.profile === 'CONFIDENTIAL_BACKEND' || app.profile === 'SERVICE_ACCOUNT_ONLY';
        return (
          <div key={i} className="bg-white border rounded p-4 space-y-3">
            <div className="flex justify-between items-center">
              <div className="text-sm font-semibold flex items-center gap-2">
                <span>App #{i + 1}</span>
                {app._existing && (
                  <span className="px-2 py-0.5 rounded text-xs bg-blue-50 text-blue-800 border border-blue-200 font-normal">
                    already exists
                  </span>
                )}
              </div>
              <button
                onClick={() => removeApp(i)}
                disabled={app._existing}
                className="text-xs text-red-700 hover:underline disabled:opacity-50 disabled:no-underline disabled:cursor-not-allowed"
              >
                Remove
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <label className="block">
                <div className="text-xs text-slate-600 mb-1">Slug *</div>
                <input
                  value={app.slug}
                  onChange={(e) => patchApp(i, { slug: e.target.value })}
                  placeholder="safesound-backend"
                  className="w-full border rounded px-2 py-1 font-mono text-sm"
                />
                {slugBad && (
                  <div className="text-red-700 text-xs mt-1">
                    Must match <code className="font-mono">^[a-z0-9]([a-z0-9-]*[a-z0-9])?$</code>
                  </div>
                )}
                {dupSlug && (
                  <div className="text-red-700 text-xs mt-1">Duplicate slug in this wizard</div>
                )}
              </label>

              <label className="block">
                <div className="text-xs text-slate-600 mb-1">Display name *</div>
                <input
                  value={app.displayName}
                  onChange={(e) => patchApp(i, { displayName: e.target.value })}
                  placeholder="Safesound backend"
                  className="w-full border rounded px-2 py-1 text-sm"
                />
              </label>
            </div>

            <label className="block">
              <div className="text-xs text-slate-600 mb-1">Profile</div>
              <select
                value={app.profile}
                onChange={(e) => {
                  const profile = e.target.value as AppProfile;
                  const next: Partial<WizardApp> = { profile };
                  if (profile === 'SPA_PKCE') next.saPermissions = [];
                  patchApp(i, next);
                }}
                className="border rounded px-2 py-1 text-sm"
              >
                <option value="CONFIDENTIAL_BACKEND">{APP_PROFILE_LABELS.CONFIDENTIAL_BACKEND}</option>
                <option value="SPA_PKCE">{APP_PROFILE_LABELS.SPA_PKCE}</option>
                <option value="SERVICE_ACCOUNT_ONLY">{APP_PROFILE_LABELS.SERVICE_ACCOUNT_ONLY}</option>
              </select>
            </label>

            <div>
              <div className="text-xs text-slate-600 mb-1">Audience</div>
              {otherSlugs.length === 0 ? (
                <div className="text-xs text-slate-500">
                  No other apps in this wizard yet — add more apps to populate audience options.
                </div>
              ) : (
                <div className="space-y-1">
                  {otherSlugs.map(s => (
                    <label key={s} className="flex items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={app.audience.includes(s)}
                        onChange={(e) => {
                          const next = e.target.checked
                            ? Array.from(new Set([...app.audience, s]))
                            : app.audience.filter(x => x !== s);
                          patchApp(i, { audience: next });
                        }}
                      />
                      <span className="font-mono text-xs">{s}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>

            {showSa && (
              <div>
                <div className="text-xs text-slate-600 mb-1">Service account permissions</div>
                <div className="space-y-1">
                  {SA_PERMISSION_PRESET.map(p => (
                    <label key={p} className="flex items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={app.saPermissions.includes(p)}
                        onChange={(e) => {
                          const next = e.target.checked
                            ? Array.from(new Set([...app.saPermissions, p]))
                            : app.saPermissions.filter(x => x !== p);
                          patchApp(i, { saPermissions: next });
                        }}
                      />
                      <span className="font-mono text-xs">{p}</span>
                    </label>
                  ))}
                </div>
                <div className="text-xs text-slate-500 mt-1">
                  Granted to the client's service account on the auth-manager management client.
                </div>
              </div>
            )}
          </div>
        );
      })}

      <button
        type="button"
        onClick={addApp}
        className="bg-white border rounded px-3 py-1.5 text-sm hover:bg-slate-50"
      >
        + Add app
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 3 — Manifest (optional)
// ---------------------------------------------------------------------------

function Step3Manifest({
  file, onChange,
}: { file: File | undefined; onChange: (f: File | undefined) => void }) {
  return (
    <div className="bg-white border rounded p-6 space-y-4">
      <div className="text-sm text-slate-500">Step 3 of 5 — Manifest (optional)</div>
      <FileDrop
        accept=".yaml,.yml,application/yaml,text/yaml"
        prompt={<>Drop your <code className="font-mono">&lt;tenant&gt;-manifest.yaml</code> here</>}
        validate={(f) => {
          const lower = f.name.toLowerCase();
          if (!lower.endsWith('.yaml') && !lower.endsWith('.yml')) {
            return 'Only .yaml or .yml files are accepted';
          }
          return null;
        }}
        file={file}
        onChange={onChange}
      />
      <div className="text-xs text-slate-500">
        Applied with <code className="font-mono">applyRoles=true</code>; first apply for a new
        tenant has no hash tripwire concern.
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 4 — Theme (optional)
// ---------------------------------------------------------------------------

function Step4Theme({
  file, onChange,
}: { file: File | undefined; onChange: (f: File | undefined) => void }) {
  return (
    <div className="bg-white border rounded p-6 space-y-4">
      <div className="text-sm text-slate-500">Step 4 of 5 — Theme (optional)</div>
      <FileDrop
        accept=".zip,application/zip,application/x-zip-compressed"
        prompt={<>Drop your theme <code className="font-mono">.zip</code> here</>}
        validate={(f) => {
          if (!f.name.toLowerCase().endsWith('.zip')) return 'Only .zip files are accepted';
          return null;
        }}
        file={file}
        onChange={onChange}
      />
      <div className="text-xs text-slate-500">
        Theme upload triggers a KC pod rolling restart (~30–90s); KC stays available throughout via
        the 3-replica cluster.
      </div>
    </div>
  );
}

// Generic file-drop UI shared by steps 3 and 4. Kept inline (not exported)
// because the wizard owns its presentation; the BrandingTab drop zone is
// upload-on-drop whereas this one just selects a File for later submission.
function FileDrop({
  accept, prompt, validate, file, onChange,
}: {
  accept: string;
  prompt: React.ReactNode;
  validate: (f: File) => string | null;
  file: File | undefined;
  onChange: (f: File | undefined) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  function pick(f: File) {
    const err = validate(f);
    if (err) { setLocalError(err); return; }
    setLocalError(null);
    onChange(f);
  }

  return (
    <div className="space-y-2">
      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          const f = e.dataTransfer.files?.[0];
          if (f) pick(f);
        }}
        onClick={() => inputRef.current?.click()}
        className={
          'border-2 border-dashed rounded p-6 text-center cursor-pointer transition-colors ' +
          (dragOver ? 'border-slate-900 bg-slate-50' : 'border-slate-300 bg-white hover:border-slate-500')
        }
      >
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) pick(f);
            if (inputRef.current) inputRef.current.value = '';
          }}
        />
        <div className="text-sm text-slate-700">{prompt}</div>
        <div className="text-xs text-slate-500 mt-1">or click to choose a file</div>
      </div>
      {file && (
        <div className="flex items-center gap-3 text-sm">
          <span className="text-slate-700">
            Selected: <span className="font-mono">{file.name}</span>{' '}
            <span className="text-slate-500">({formatBytes(file.size)})</span>
          </span>
          <button onClick={() => onChange(undefined)} className="text-xs text-red-700 hover:underline">
            Clear
          </button>
        </div>
      )}
      {localError && <div className="text-red-700 text-xs">{localError}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 5 — Review
// ---------------------------------------------------------------------------

function Step5Review({
  basics, apps, manifestFile, themeFile,
}: {
  basics: WizardBasics;
  apps: WizardApp[];
  manifestFile: File | undefined;
  themeFile: File | undefined;
}) {
  return (
    <div className="space-y-4">
      <div className="bg-white border rounded p-4">
        <div className="text-sm font-semibold mb-2">Tenant</div>
        <dl className="grid grid-cols-[120px_1fr] gap-y-1 text-sm">
          <dt className="text-slate-500">slug</dt>
          <dd className="font-mono">{basics.slug}</dd>
          <dt className="text-slate-500">realm</dt>
          <dd className="font-mono">t-{basics.slug}</dd>
          <dt className="text-slate-500">display</dt>
          <dd>{basics.displayName}</dd>
          <dt className="text-slate-500">admin email</dt>
          <dd>{basics.adminEmail}</dd>
          <dt className="text-slate-500">hostnames</dt>
          <dd>
            {basics.hostnames.map((h, i) => (
              <div key={i} className="font-mono">
                {h.host}
                {h.backend ? <span className="text-slate-500"> → {h.backend}</span> : null}
              </div>
            ))}
          </dd>
        </dl>
      </div>

      <div className="bg-white border rounded p-4">
        <div className="text-sm font-semibold mb-2">Apps ({apps.length})</div>
        {apps.length === 0 ? (
          <div className="text-sm text-slate-500">No apps — tenant will be created without any clients.</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-left text-slate-500 text-xs">
              <tr>
                <th className="py-1 pr-3">Slug</th>
                <th className="py-1 pr-3">Profile</th>
                <th className="py-1 pr-3">Audience</th>
                <th className="py-1 pr-3">SA perms</th>
              </tr>
            </thead>
            <tbody>
              {apps.map((a, i) => (
                <tr key={i} className="border-t">
                  <td className="py-1 pr-3 font-mono">{a.slug}</td>
                  <td className="py-1 pr-3">{APP_PROFILE_LABELS[a.profile]}</td>
                  <td className="py-1 pr-3 font-mono text-xs">
                    {a.audience.length === 0 ? '—' : a.audience.join(', ')}
                  </td>
                  <td className="py-1 pr-3 font-mono text-xs">
                    {a.saPermissions.length === 0 ? '—' : a.saPermissions.join(', ')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="bg-white border rounded p-4 space-y-1 text-sm">
        <div><span className="text-slate-500">Manifest:</span>{' '}
          {manifestFile
            ? <span className="font-mono">{manifestFile.name} ({formatBytes(manifestFile.size)})</span>
            : <span className="text-slate-500">(none)</span>}
        </div>
        <div><span className="text-slate-500">Theme:</span>{' '}
          {themeFile
            ? <span className="font-mono">{themeFile.name} ({formatBytes(themeFile.size)})</span>
            : <span className="text-slate-500">(none)</span>}
        </div>
      </div>

      <div className="bg-slate-50 border rounded p-4 text-sm space-y-2">
        <div className="font-semibold text-slate-700">What I'll do automatically (in order):</div>
        <ol className="list-decimal pl-5 space-y-0.5 text-slate-700">
          <li>Create tenant (realm + bootstrap + CF DNS)</li>
          {apps.length > 0 && <li>Create {apps.length} app{apps.length === 1 ? '' : 's'} with the profiles above</li>}
          {apps.some(a => a.saPermissions.length > 0) && (
            <li>Grant SA permissions to {apps.filter(a => a.saPermissions.length > 0).map(a => a.slug).join(', ')}</li>
          )}
          {manifestFile && <li>Apply manifest (perms + roles + IdP + defaults)</li>}
          {themeFile && <li>Upload theme</li>}
        </ol>
        <div className="font-semibold text-slate-700 pt-2">What you'll do after:</div>
        <ul className="list-disc pl-5 space-y-0.5 text-slate-700">
          <li>Add the broker URI to your Google OAuth Console</li>
          <li>Share each confidential app's <code className="font-mono">client_secret</code> with the tenant team (revealed once on the next page)</li>
        </ul>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Generate progress panel
// ---------------------------------------------------------------------------

function GenerateProgressPanel({ rows }: { rows: ProgressRow[] }) {
  return (
    <div className="bg-slate-900 text-slate-100 rounded p-4 font-mono text-sm">
      <div className="mb-2 text-slate-300">Generating tenant…</div>
      <ul className="space-y-1">
        {rows.map(r => (
          <li key={r.key} className="flex items-start gap-2">
            <span className="w-5">{statusGlyph(r.status)}</span>
            <span className={r.status === 'error' ? 'text-red-300' : ''}>{r.label}</span>
            {r.detail && (
              <span className="text-red-300 text-xs ml-2 break-all">— {r.detail}</span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function statusGlyph(s: ProgressStatus): string {
  switch (s) {
    case 'pending': return '·';
    case 'in_progress': return '…';
    case 'success': return '✓';
    case 'error': return '✗';
  }
}

// ---------------------------------------------------------------------------
// Success page
// ---------------------------------------------------------------------------

function SuccessPage({
  tenant, apps, revealedSecrets, onReveal, onViewTenant, onOnboardAnother,
}: {
  tenant: Tenant;
  apps: CreatedAppInfo[];
  revealedSecrets: Set<string>;
  onReveal: (clientId: string, secret: string | null) => void;
  onViewTenant: () => void;
  onOnboardAnother: () => void;
}) {
  // Only apps that actually got a clientSecret back are confidential — SPA
  // apps + pre-existing apps (whose secret was captured on a prior run) have
  // clientSecret === null and shouldn't appear in the env-vars block.
  const confidentialApps = apps.filter(a => a.clientSecret !== null);
  const realmName = tenant.realmName ?? `t-${tenant.slug}`;
  const upperSlug = tenant.slug.toUpperCase().replace(/-/g, '_');

  // Always-render lines: apply to any tenant regardless of confidential apps.
  const alwaysRenderLines = [
    `AUTH_LIB_ISSUER_URI         = https://auth.mcp-mesh.io/auth/realms/${realmName}`,
    `AUTH_LIB_PERMISSIONS_SOURCE = claims`,
    `KC_BASE                     = https://auth.mcp-mesh.io/auth`,
    `AUTH_MGR_BASE               = http://auth-platform-auth-manager.auth-platform.svc.cluster.local:8080`,
    `${upperSlug}_TENANT_SLUG = ${tenant.slug}`,
  ];

  // For the Copy-block button: include CLIENT_ID + AUDIENCES per confidential
  // app (with a section header when >1) but NEVER the secret — operator copies
  // the secret separately via the Reveal button.
  const copyBlock = (() => {
    const sections: string[] = [];
    if (confidentialApps.length > 0) {
      confidentialApps.forEach((a, idx) => {
        const header = confidentialApps.length > 1 ? `# ${a.slug}\n` : '';
        sections.push(
          `${header}AUTH_LIB_CLIENT_ID     = ${a.slug}\n` +
          `AUTH_LIB_AUDIENCES     = ${a.slug}`
        );
        if (idx < confidentialApps.length - 1) sections.push('');
      });
      sections.push('');
    }
    sections.push(alwaysRenderLines.join('\n'));
    return sections.join('\n');
  })();

  // Fix #2: fetch enabled IdPs on the realm — drives the manual-steps section.
  const [enabledIdps, setEnabledIdps] = useState<IdentityProviderDto[]>([]);
  useEffect(() => {
    api.listIdentityProviders(tenant.slug)
      .then(idps => setEnabledIdps(idps.filter(i => i.enabled)))
      .catch(() => { /* don't fail the success page if this errors */ });
  }, [tenant.slug]);

  return (
    <div className="space-y-6">
      <div className="bg-emerald-50 border border-emerald-200 rounded p-4 flex items-center gap-3">
        <span className="text-emerald-700 text-xl">✓</span>
        <div>
          <div className="font-semibold text-emerald-900">
            Tenant '{tenant.slug}' onboarded
          </div>
          <div className="text-xs text-emerald-800">Realm: <code className="font-mono">{realmName}</code></div>
        </div>
      </div>

      {confidentialApps.length > 0 && (
        <section className="bg-white border rounded p-4 space-y-3">
          <div className="text-sm font-semibold">Secrets — reveal once and share securely</div>
          <div className="space-y-2">
            {confidentialApps.map(a => {
              const revealed = revealedSecrets.has(a.clientId);
              return (
                <div key={a.clientId} className="flex items-center gap-3 text-sm">
                  <div className="font-mono text-xs w-64 truncate" title={a.clientId}>{a.clientId}</div>
                  <code className="flex-1 bg-slate-100 px-2 py-1 rounded font-mono text-xs">
                    {revealed
                      ? (a.clientSecret ?? '<no secret returned>')
                      : '••••••••••••••••••••••••'}
                  </code>
                  {!revealed && (
                    <button
                      onClick={() => onReveal(a.clientId, a.clientSecret)}
                      className="bg-slate-900 text-white px-2 py-1 rounded text-xs hover:bg-slate-700"
                    >
                      Reveal &amp; copy
                    </button>
                  )}
                  {revealed && (
                    <span className="text-xs text-slate-500">copied to clipboard</span>
                  )}
                </div>
              );
            })}
          </div>
          <div className="text-xs text-slate-500">
            Clicking Reveal copies the value to the clipboard once; this UI does not retain it
            for a second reveal.
          </div>
        </section>
      )}

      <div className="text-xs text-slate-600 bg-slate-50 border rounded px-3 py-2">
        Tip: Download the full onboarding bundle below for a single-file handoff (env vars + library setup + theming + user migration docs).
      </div>

      <section className="bg-white border rounded p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="text-sm font-semibold">Env vars for tenant team's helm-values</div>
          <button
            onClick={() => navigator.clipboard.writeText(copyBlock).catch(() => { /* clipboard blocked */ })}
            className="text-xs bg-slate-900 text-white px-2 py-1 rounded hover:bg-slate-700"
          >
            Copy block
          </button>
        </div>
        <div className="bg-slate-50 border rounded p-3 text-xs font-mono overflow-x-auto space-y-3">
          {confidentialApps.map((a, idx) => {
            const revealed = revealedSecrets.has(a.clientId);
            return (
              <div key={a.clientId} className="space-y-1">
                {confidentialApps.length > 1 && (
                  <div className="text-slate-500"># {a.slug}</div>
                )}
                <div>AUTH_LIB_CLIENT_ID     = {a.slug}</div>
                <div className="flex items-center gap-2">
                  <span>AUTH_LIB_CLIENT_SECRET =</span>
                  {revealed ? (
                    <code className="bg-white border px-1 rounded">
                      {a.clientSecret ?? '<no secret returned>'}
                    </code>
                  ) : (
                    <button
                      onClick={() => onReveal(a.clientId, a.clientSecret)}
                      className="bg-slate-900 text-white px-2 py-0.5 rounded text-xs hover:bg-slate-700"
                    >
                      Reveal once + copy
                    </button>
                  )}
                </div>
                <div>AUTH_LIB_AUDIENCES     = {a.slug}</div>
                {idx < confidentialApps.length - 1 && <div className="h-1" />}
              </div>
            );
          })}
          <pre className="whitespace-pre">{alwaysRenderLines.join('\n')}</pre>
        </div>
      </section>

      <section className="bg-white border rounded p-4 space-y-3">
        <div className="text-sm font-semibold">Manual steps</div>
        {enabledIdps.length === 0 ? (
          <div className="text-sm text-slate-700">
            □ No identity providers enabled on this realm — sign-in will require manual user
            creation. Visit the Identity Providers tab on the tenant detail page to enable
            Google or GitHub.
          </div>
        ) : (
          enabledIdps.map(idp => {
            const brokerUrl = `https://auth.mcp-mesh.io/auth/realms/${realmName}/broker/${idp.id}/endpoint`;
            const openHref =
              idp.id === 'google' ? 'https://console.cloud.google.com/apis/credentials' :
              idp.id === 'github' ? 'https://github.com/settings/developers' :
              undefined;
            return (
              <BrokerUriRow
                key={idp.id}
                label={`Add this URI to your ${idp.displayName} OAuth Console:`}
                uri={brokerUrl}
                openHref={openHref}
              />
            );
          })
        )}
        {confidentialApps.length > 0 && (
          <div className="text-sm text-slate-700">
            □ Share the client_secret(s) above with the tenant team via a secure channel
            (1Password / Bitwarden / Signal).
          </div>
        )}
      </section>

      <div className="flex gap-3">
        <button onClick={onViewTenant} className="bg-slate-900 text-white px-3 py-1.5 rounded text-sm hover:bg-slate-700">
          View tenant
        </button>
        <button onClick={onOnboardAnother} className="bg-white border px-3 py-1.5 rounded text-sm hover:bg-slate-50">
          Onboard another
        </button>
        <button
          onClick={async () => {
            try { await api.downloadOnboardingBundle(tenant.id); }
            catch (e) { alert('Download failed: ' + (e instanceof Error ? e.message : String(e))); }
          }}
          className="bg-white border px-3 py-1.5 rounded text-sm hover:bg-slate-50"
        >
          Download bundle (.zip)
        </button>
      </div>
    </div>
  );
}

function BrokerUriRow({ label, uri, openHref }: { label: string; uri: string; openHref?: string }) {
  return (
    <div className="text-sm text-slate-700 space-y-1">
      <div>□ {label}</div>
      <div className="flex items-center gap-2 pl-4">
        <code className="flex-1 bg-slate-50 border rounded px-2 py-1 text-xs font-mono break-all">{uri}</code>
        <button
          onClick={() => navigator.clipboard.writeText(uri).catch(() => { /* clipboard blocked */ })}
          className="text-xs bg-slate-900 text-white px-2 py-1 rounded hover:bg-slate-700"
        >
          Copy
        </button>
        {openHref && (
          <a href={openHref} target="_blank" rel="noopener noreferrer"
             className="text-xs text-blue-700 hover:underline">
            Open ↗
          </a>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// utils
// ---------------------------------------------------------------------------

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
