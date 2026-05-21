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

  return { valid: errors.length === 0, errors, ruleErrors, targetErrors };
}

export function deepEqual(a: RoutingConfig, b: RoutingConfig): boolean {
  if (a.rules.length !== b.rules.length) return false;
  for (let i = 0; i < a.rules.length; i++) {
    const x = a.rules[i], y = b.rules[i];
    if (x.path !== y.path || x.authMode !== y.authMode || x.target !== y.target) return false;
  }
  const ak = Object.keys(a.targets), bk = Object.keys(b.targets);
  if (ak.length !== bk.length) return false;
  for (const k of ak) {
    if (a.targets[k] !== b.targets[k]) return false;
  }
  return true;
}
