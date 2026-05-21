import { useEffect, useMemo, useState } from 'react';
import { useAuth } from 'react-oidc-context';
import type { RoutingConfig, RoutingRule } from '../../api/types';
import { useReplaceRoutesMutation, useRoutesQuery } from './useRoutesQuery';
import { deepEqual, validate } from './validate';
import RulesTable from './RulesTable';
import TargetsTable, { type TargetEntry } from './TargetsTable';

interface Props {
  slug: string;
}

function targetsToEntries(targets: Record<string, string>): TargetEntry[] {
  return Object.entries(targets).map(([key, value]) => ({ key, value }));
}

function entriesToTargets(entries: TargetEntry[]): Record<string, string> {
  // Later entries with the same key win, but validation surfaces duplicates first.
  const out: Record<string, string> = {};
  for (const e of entries) {
    if (e.key.trim() === '') continue;
    out[e.key] = e.value;
  }
  return out;
}

/**
 * Reads tenant-admin role from the OIDC JWT's
 * resource_access.usermanagement.roles claim (matches backend
 * TenantSecurity.checkRoleClaim). Note: this only signals whether the
 * UI should render in edit mode — the backend still enforces 403.
 */
function useIsTenantAdmin(): boolean {
  const auth = useAuth();
  if (!auth.isAuthenticated || !auth.user) return false;
  const ra = auth.user.profile?.resource_access as
    | Record<string, { roles?: string[] }>
    | undefined;
  const roles = ra?.usermanagement?.roles;
  return Array.isArray(roles) && roles.includes('tenant-admin');
}

export default function RoutesTab({ slug }: Props) {
  const isTenantAdmin = useIsTenantAdmin();
  const query = useRoutesQuery(slug);
  const mutation = useReplaceRoutesMutation(slug);

  const [rules, setRules] = useState<RoutingRule[]>([]);
  const [targetEntries, setTargetEntries] = useState<TargetEntry[]>([]);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  // Seed local state when the server data arrives or changes.
  useEffect(() => {
    if (query.data) {
      setRules(query.data.rules);
      setTargetEntries(targetsToEntries(query.data.targets));
    }
  }, [query.data]);

  const currentConfig: RoutingConfig = useMemo(
    () => ({ rules, targets: entriesToTargets(targetEntries) }),
    [rules, targetEntries]
  );

  const validation = useMemo(() => validate(currentConfig), [currentConfig]);

  const duplicateTargetKeys = useMemo(() => {
    const seen = new Set<string>();
    const dups = new Set<string>();
    for (const e of targetEntries) {
      if (e.key.trim() === '') continue;
      if (seen.has(e.key)) dups.add(e.key);
      seen.add(e.key);
    }
    return dups;
  }, [targetEntries]);

  const targetKeys = useMemo(
    () => targetEntries.map(e => e.key).filter(k => k.trim() !== ''),
    [targetEntries]
  );

  const hasChanges = query.data ? !deepEqual(currentConfig, query.data) : false;
  const hasDuplicateTargets = duplicateTargetKeys.size > 0;
  const canSave =
    isTenantAdmin &&
    validation.valid &&
    !hasDuplicateTargets &&
    hasChanges &&
    !mutation.isPending;

  const reset = () => {
    if (!query.data) return;
    setRules(query.data.rules);
    setTargetEntries(targetsToEntries(query.data.targets));
    setSaveMessage(null);
    mutation.reset();
  };

  const save = () => {
    setSaveMessage(null);
    mutation.mutate(currentConfig, {
      onSuccess: () => setSaveMessage('Routes saved'),
    });
  };

  if (query.isLoading) return <div>Loading…</div>;
  if (query.isError) return <div className="text-red-700">{String(query.error)}</div>;
  if (!query.data) return null;

  return (
    <div className="space-y-4 pb-20">
      {!isTenantAdmin && (
        <div className="bg-amber-50 border border-amber-200 rounded p-3 text-sm text-amber-900">
          You're viewing in read-only mode. Tenant-admins can edit.
        </div>
      )}

      {isTenantAdmin && hasChanges && (validation.errors.length > 0 || hasDuplicateTargets) && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
          <div className="font-medium mb-1">Fix these before saving:</div>
          <ul className="list-disc ml-5">
            {validation.errors.map((e, i) => <li key={'v' + i}>{e}</li>)}
            {hasDuplicateTargets && <li>Duplicate target names: {Array.from(duplicateTargetKeys).join(', ')}</li>}
          </ul>
        </div>
      )}

      {saveMessage && (
        <div className="bg-emerald-50 border border-emerald-200 rounded p-3 text-sm text-emerald-900 flex justify-between">
          <span>{saveMessage}</span>
          <button onClick={() => setSaveMessage(null)} className="text-emerald-700 hover:underline">dismiss</button>
        </div>
      )}

      {mutation.isError && (
        <div className="bg-red-50 border border-red-200 rounded p-3 text-sm text-red-900">
          {String(mutation.error)}
        </div>
      )}

      <RulesTable
        rules={rules}
        targetKeys={targetKeys}
        ruleErrors={validation.ruleErrors}
        readOnly={!isTenantAdmin}
        onChange={setRules}
      />

      <TargetsTable
        targets={targetEntries}
        duplicateKeys={duplicateTargetKeys}
        targetErrors={validation.targetErrors}
        readOnly={!isTenantAdmin}
        onChange={setTargetEntries}
      />

      {isTenantAdmin && (
        <div className="sticky bottom-0 bg-white border-t -mx-6 px-6 py-3 flex items-center justify-between">
          <div className="text-xs text-slate-500">
            {hasChanges ? 'Unsaved changes' : 'No changes'}
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={reset}
              disabled={!hasChanges || mutation.isPending}
              className="border px-3 py-1 rounded text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-50"
            >
              Reset
            </button>
            <button
              type="button"
              onClick={save}
              disabled={!canSave}
              className="bg-slate-900 text-white px-3 py-1 rounded text-sm hover:bg-slate-700 disabled:opacity-50"
            >
              {mutation.isPending ? 'Saving…' : 'Save'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
