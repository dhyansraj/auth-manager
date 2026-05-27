import type { RoutingConfig } from '../../api/types';

export interface RuleError {
  index: number;
  field: 'path' | 'target';
  message: string;
}

export interface TargetError {
  key: string;
  message: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  ruleErrors: RuleError[];
  targetErrors: TargetError[];
}

/**
 * Mirrors backend invariants from RoutingConfig.java + extra UI-only checks:
 *  - rules non-empty
 *  - at least one rule with path === '/*' (catch-all)
 *  - every rule.path non-empty
 *  - every rule.target exists in targets map
 *  - every target value non-empty
 *  - no duplicate rule.path entries (first-match-wins would mask later rules)
 */
export function validate(config: RoutingConfig): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const ruleErrors: RuleError[] = [];
  const targetErrors: TargetError[] = [];

  if (!config.rules || config.rules.length === 0) {
    errors.push('At least one rule is required.');
  }

  const hasCatchAll = config.rules.some(r => r.path === '/*');
  if (!hasCatchAll && config.rules.length > 0) {
    errors.push('At least one rule must have path "/*" (catch-all).');
  }

  const targetKeys = new Set(Object.keys(config.targets));
  const seenPaths = new Map<string, number>();

  config.rules.forEach((rule, i) => {
    if (!rule.path || rule.path.trim() === '') {
      ruleErrors.push({ index: i, field: 'path', message: 'Path is required' });
    } else {
      const prev = seenPaths.get(rule.path);
      if (prev !== undefined) {
        ruleErrors.push({ index: i, field: 'path', message: `Duplicate of rule #${prev + 1}` });
      } else {
        seenPaths.set(rule.path, i);
      }
    }
    if (!rule.target || !targetKeys.has(rule.target)) {
      ruleErrors.push({
        index: i,
        field: 'target',
        message: rule.target ? `Unknown target "${rule.target}"` : 'Target is required',
      });
    }
    if (rule.bypassCsrf && rule.authMode !== 'REQUIRED') {
      warnings.push(
        `Rule #${i + 1}: Bypass CSRF only applies when Auth Mode is REQUIRED — otherwise CSRF doesn't run anyway.`
      );
    }
    const sp = (rule.stripPrefix ?? '').trim();
    if (sp !== '') {
      if (sp.endsWith('/*')) {
        warnings.push(
          `Rule #${i + 1}: Strip prefix "${sp}" ends in "/*" — you probably meant to drop the wildcard (e.g. "${sp.slice(0, -2)}").`
        );
      }
      if (rule.path && rule.path.trim() !== '') {
        // Compare against the rule path with any trailing "/*" removed, since
        // the prefix is matched against concrete request paths, not the glob.
        const rulePathBase = rule.path.endsWith('/*') ? rule.path.slice(0, -2) : rule.path;
        if (rulePathBase !== sp && !rulePathBase.startsWith(sp)) {
          warnings.push(
            `Rule #${i + 1}: Strip prefix "${sp}" is not a prefix of path "${rule.path}" — likely a typo (rewrite will be a no-op).`
          );
        }
      }
    }
  });

  Object.entries(config.targets).forEach(([k, v]) => {
    if (!v || v.trim() === '') {
      targetErrors.push({ key: k, message: `Target "${k}" has empty URL` });
    }
  });

  if (ruleErrors.length > 0) {
    errors.push(`${ruleErrors.length} rule field(s) need attention.`);
  }
  if (targetErrors.length > 0) {
    errors.push(`${targetErrors.length} target(s) have empty URLs.`);
  }

  return { valid: errors.length === 0, errors, warnings, ruleErrors, targetErrors };
}

export function deepEqual(a: RoutingConfig, b: RoutingConfig): boolean {
  // Rules are order-insensitive here: the server auto-sorts by specificity
  // on save, so the freshly-returned list may differ in order from the
  // user's just-saved local state. Comparing as a map-by-path keeps the
  // dirty-check stable (no spurious "unsaved changes" flicker right after
  // a successful save). Duplicate paths are blocked by validate() above.
  if (a.rules.length !== b.rules.length) return false;
  const byPath = new Map<string, typeof a.rules[number]>();
  for (const x of a.rules) byPath.set(x.path, x);
  for (const y of b.rules) {
    const x = byPath.get(y.path);
    if (!x) return false;
    if (x.authMode !== y.authMode || x.target !== y.target) return false;
    // Treat omitted / false / undefined as equivalent — server sends the
    // canonical form (false), local edits may set it explicitly.
    if (Boolean(x.bypassCsrf) !== Boolean(y.bypassCsrf)) return false;
    // Treat omitted / null / undefined / "" as equivalent for the optional
    // per-rule permission gate.
    const xp = (x.requiredPermission ?? '').trim();
    const yp = (y.requiredPermission ?? '').trim();
    if (xp !== yp) return false;
    // Same omitted/null/empty equivalence for the optional prefix strip.
    const xs = (x.stripPrefix ?? '').trim();
    const ys = (y.stripPrefix ?? '').trim();
    if (xs !== ys) return false;
  }
  const ak = Object.keys(a.targets), bk = Object.keys(b.targets);
  if (ak.length !== bk.length) return false;
  for (const k of ak) {
    if (a.targets[k] !== b.targets[k]) return false;
  }
  return true;
}
