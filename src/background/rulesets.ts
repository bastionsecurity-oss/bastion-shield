// Bastion Shield service worker — planning which static rulesets to enable
// (ARCHITECTURE §3, §4.1). Pure: given the wanted lists in manifest order and
// the budgets, decide what fits and why the rest does not. Main rulesets win
// over `.regex` companions; when the regex budget is exceeded only the
// companion is skipped, never the main list.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { LIMITS, REGEX_RULESET_SUFFIX, RULESET_PARAMS } from '../shared/constants.ts';
import type { BuildMeta, Settings } from '../shared/types.ts';

export interface RulesetCandidate {
  rulesetId: string;
  listId: string;
  rules: number;
  regex: boolean;
}

/** Stable error codes the UI can translate. */
export const LIST_ERROR = {
  RULE_LIMIT: 'rule-limit',
  REGEX_LIMIT: 'regex-limit',
  RULESET_LIMIT: 'ruleset-limit',
  MISSING: 'missing-ruleset',
} as const;

export interface RulesetPlan {
  enabled: string[];
  /** listId -> error code (or browser error text). */
  errors: Record<string, string>;
  usedRules: number;
  usedRegex: number;
}

/**
 * Wanted rulesets in manifest order (importance order), filtered to the ones
 * declared in the manifest. Unknown ids would make updateEnabledRulesets fail.
 */
export function wantedRulesets(meta: BuildMeta | null, settings: Settings, manifestOrder: readonly string[]): { candidates: RulesetCandidate[]; missing: Record<string, string> } {
  const declared = new Map(manifestOrder.map((id, i) => [id, i]));
  const missing: Record<string, string> = {};
  const candidates: RulesetCandidate[] = [];
  for (const list of meta?.lists ?? []) {
    // The params ruleset follows privacy.stripParams, not the list toggles.
    if (list.id === RULESET_PARAMS) continue;
    if (!settings.lists[list.id]) continue;
    const ids = Array.isArray(list.rulesetIds) && list.rulesetIds.length > 0 ? list.rulesetIds : [list.id];
    let any = false;
    for (const rid of ids) {
      if (declared.size > 0 && !declared.has(rid)) continue;
      const regex = rid.endsWith(REGEX_RULESET_SUFFIX);
      candidates.push({ rulesetId: rid, listId: list.id, rules: regex ? list.regexRuleCount || 0 : list.ruleCount || 0, regex });
      any = true;
    }
    if (!any) missing[list.id] = LIST_ERROR.MISSING;
  }
  if (settings.privacy.stripParams && (declared.size === 0 || declared.has(RULESET_PARAMS))) {
    // Built-in ruleset; its size is small (one rule per parameter) and not in meta.lists.
    const paramsList = meta?.lists.find((l) => l.id === RULESET_PARAMS);
    candidates.push({ rulesetId: RULESET_PARAMS, listId: RULESET_PARAMS, rules: paramsList?.ruleCount ?? 0, regex: false });
  }
  const pos = (rid: string) => declared.get(rid) ?? Number.MAX_SAFE_INTEGER;
  candidates.sort((a, b) => pos(a.rulesetId) - pos(b.rulesetId));
  return { candidates, missing };
}

/**
 * Greedy fit in importance order: main rulesets first, then regex companions.
 * `ruleBudget` is the total number of static rules we may have enabled
 * (currently enabled + getAvailableStaticRuleCount()).
 */
export function planRulesets(
  candidates: readonly RulesetCandidate[],
  ruleBudget: number,
  maxRegex: number = LIMITS.MAX_STATIC_REGEX_RULES,
  maxEnabled: number = LIMITS.MAX_ENABLED_STATIC_RULESETS,
): RulesetPlan {
  const enabled: string[] = [];
  const errors: Record<string, string> = {};
  let usedRules = 0;
  let usedRegex = 0;
  const failedLists = new Set<string>();
  const pass = (regexPass: boolean) => {
    for (const c of candidates) {
      if (c.regex !== regexPass) continue;
      if (failedLists.has(c.listId)) continue;
      if (enabled.length >= maxEnabled) {
        if (!c.regex) failedLists.add(c.listId);
        errors[c.listId] ??= LIST_ERROR.RULESET_LIMIT;
        continue;
      }
      if (usedRules + c.rules > ruleBudget) {
        if (!c.regex) failedLists.add(c.listId);
        errors[c.listId] ??= LIST_ERROR.RULE_LIMIT;
        continue;
      }
      if (c.regex && usedRegex + c.rules > maxRegex) {
        errors[c.listId] ??= LIST_ERROR.REGEX_LIMIT;
        continue;
      }
      enabled.push(c.rulesetId);
      usedRules += c.rules;
      if (c.regex) usedRegex += c.rules;
    }
  };
  pass(false);
  pass(true);
  return { enabled, errors, usedRules, usedRegex };
}

/** Rule count of a set of enabled rulesets according to the build metadata. */
export function countRules(meta: BuildMeta | null, rulesetIds: readonly string[]): { rules: number; regex: number } {
  let rules = 0;
  let regex = 0;
  const byRuleset = new Map<string, { n: number; regex: boolean }>();
  for (const l of meta?.lists ?? []) {
    for (const rid of l.rulesetIds ?? [l.id]) {
      const isRegex = rid.endsWith(REGEX_RULESET_SUFFIX);
      byRuleset.set(rid, { n: isRegex ? l.regexRuleCount || 0 : l.ruleCount || 0, regex: isRegex });
    }
  }
  for (const id of rulesetIds) {
    const r = byRuleset.get(id);
    if (!r) continue;
    rules += r.n;
    if (r.regex) regex += r.n;
  }
  return { rules, regex };
}
