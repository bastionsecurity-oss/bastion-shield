// Bastion Shield service worker — dynamic and session DNR rule generation
// (ARCHITECTURE §4.3, §4.5, §4.6). Pure functions: inputs are settings and
// site maps, outputs are plain rule objects. apply.ts sends them to Chrome.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { LIMITS, PRIORITY, RULE_ID } from '../shared/constants.ts';
import type { BlockingMode, Settings, SitesMap } from '../shared/types.ts';
import type { DnrRule } from '../compiler/types.ts';
import { explicitField, isDnrDomain, layerScopes } from './sites.ts';
import { canonicalJson } from './util.ts';

/** Debounce redirect priority; see PRIORITY.DEBOUNCE for the rationale. */
export const DEBOUNCE_PRIORITY = PRIORITY.DEBOUNCE;

/** Ids 8_000_000..8_000_009 (and their 8_000_030.. companions) are reserved for nested "protection off" groups. */
const SITES_DISABLED_SLOTS = 10;
/** Ids 8_000_010..8_000_019 for Standard-mode first-party allow groups. */
const STANDARD_SLOTS = RULE_ID.GPC_HEADER - RULE_ID.STANDARD_1P_ALLOW;
/** Session ids 9_000_000.. for nested no-tab allow groups (proceed rules start at 9_100_000). */
const SESSION_DISABLED_SLOTS = 10;

/** Resource types Chromium 128+ knows. Used when the runtime enum is unavailable. */
export const FALLBACK_RESOURCE_TYPES = [
  'main_frame',
  'sub_frame',
  'stylesheet',
  'script',
  'image',
  'font',
  'object',
  'xmlhttprequest',
  'ping',
  'csp_report',
  'media',
  'websocket',
  'webtransport',
  'webbundle',
  'other',
];

export interface SiteRules {
  dynamic: DnrRule[];
  session: DnrRule[];
}

function domains(list: readonly string[]): string[] {
  return list.filter(isDnrDomain);
}

/**
 * "Protection off" rules: dynamic allowAllRequests per disabled group plus a
 * session `allow` for requests without a tab (service-worker fetches, tabId
 * -1), which allowAllRequests cannot cover.
 *
 * The setting is keyed to the top-level site, as in uBO, uBO Lite and Brave:
 * allowAllRequests on the top document already covers its whole frame tree
 * (including the disabled site's own iframes), so only main_frame is
 * matched. Matching sub_frame too would also unfilter that site's embeds on
 * every other site (BS-3).
 *
 * With `topDomains` (Chrome 145+) each group also gets an `allow` for the
 * subresources of pages whose top-level site is in the group. Chromium
 * extends allowAllRequests to subresources through per-frame state set when
 * the browser processes the navigation commit; requests the renderer sends
 * before that (the first scripts of a page, on a busy machine) were still
 * filtered right after the user switched protection off and reloaded.
 */
export function buildSitesDisabledRules(sites: SitesMap, topDomainsSupported = false): SiteRules {
  const groups = layerScopes(explicitField(sites, 'enabled'), true).filter((g) => g.value === false && g.include !== null);
  const dynamic: DnrRule[] = [];
  const session: DnrRule[] = [];
  let n = 0;
  for (const g of groups) {
    const include = domains(g.include ?? []);
    if (include.length === 0) continue;
    const exclude = domains(g.exclude);
    if (n >= SITES_DISABLED_SLOTS) break;
    const dyn: DnrRule = {
      id: RULE_ID.SITES_DISABLED + n,
      priority: PRIORITY.SITE_DISABLED,
      action: { type: 'allowAllRequests' },
      condition: { requestDomains: include, resourceTypes: ['main_frame'] },
    };
    if (exclude.length > 0) dyn.condition.excludedRequestDomains = exclude;
    dynamic.push(dyn);
    if (topDomainsSupported) {
      const top: DnrRule = {
        id: RULE_ID.SITES_DISABLED_TOP + n,
        priority: PRIORITY.SITE_DISABLED,
        action: { type: 'allow' },
        condition: { topDomains: include },
      };
      if (exclude.length > 0) top.condition.excludedTopDomains = exclude;
      dynamic.push(top);
    }
    if (n < SESSION_DISABLED_SLOTS) {
      const ses: DnrRule = {
        id: RULE_ID.SESSION_SITES_DISABLED_NO_TAB + n,
        priority: PRIORITY.SITE_DISABLED,
        action: { type: 'allow' },
        condition: { tabIds: [-1], initiatorDomains: include },
      };
      if (exclude.length > 0) ses.condition.excludedInitiatorDomains = exclude;
      session.push(ses);
    }
    n++;
  }
  return { dynamic, session };
}

/**
 * Brave "Standard" first-party semantics (§4.3): an allow at priority 20
 * masks the BLOCK_PROTECTED/REDIRECT_PROTECTED bands for same-site requests.
 * One rule per group of sites that effectively use Standard mode; nested
 * overrides are handled by layerScopes. `topDomains` conditions are only
 * emitted when the browser reports support (Chrome 145+).
 */
export function buildStandardModeRules(sites: SitesMap, defaultMode: BlockingMode, topDomainsSupported: boolean): DnrRule[] {
  const groups = layerScopes(explicitField(sites, 'mode'), defaultMode).filter((g) => g.value === 'standard');
  const out: DnrRule[] = [];
  for (const g of groups) {
    if (out.length >= STANDARD_SLOTS) break;
    const rule: DnrRule = {
      id: RULE_ID.STANDARD_1P_ALLOW + out.length,
      priority: PRIORITY.STANDARD_1P_ALLOW,
      action: { type: 'allow' },
      condition: { domainType: 'firstParty', excludedResourceTypes: ['main_frame'] },
    };
    if (g.include !== null) {
      const include = domains(g.include);
      if (include.length === 0) continue;
      rule.condition.initiatorDomains = include;
    }
    const exclude = domains(g.exclude);
    if (exclude.length > 0) {
      rule.condition.excludedInitiatorDomains = exclude;
      if (topDomainsSupported) rule.condition.excludedTopDomains = exclude;
    }
    out.push(rule);
  }
  return out;
}

/** Sec-GPC: 1 on every request (§9). Priority 5000 so it also applies where an allow rule matched. */
export function buildGpcRule(resourceTypes: readonly string[]): DnrRule {
  return {
    id: RULE_ID.GPC_HEADER,
    priority: PRIORITY.GPC_HEADER,
    action: { type: 'modifyHeaders', requestHeaders: [{ header: 'Sec-GPC', operation: 'set', value: '1' }] },
    condition: { resourceTypes: resourceTypes.length > 0 ? [...resourceTypes] : [...FALLBACK_RESOURCE_TYPES] },
  };
}

/**
 * Session rule after "proceed anyway" on the strict-block page (§4.5): an
 * `allow` for requests TO the proceeded host in that tab only, every resource
 * type including main_frame (a rule without resourceTypes would skip
 * main_frame). Other ads and trackers on the page stay blocked, unlike an
 * allowAllRequests for the whole document.
 */
export function buildProceedRule(id: number, host: string, tabId: number, resourceTypes: readonly string[] = FALLBACK_RESOURCE_TYPES): DnrRule {
  const types = resourceTypes.length > 0 ? [...resourceTypes] : [...FALLBACK_RESOURCE_TYPES];
  if (!types.includes('main_frame')) types.unshift('main_frame');
  return {
    id,
    priority: PRIORITY.PROCEED_ANYWAY,
    action: { type: 'allow' },
    condition: { requestDomains: [host], tabIds: [tabId], resourceTypes: types },
  };
}

/**
 * Fleet kill switch (policy `protectionEnabled: false`): allowAllRequests on
 * every top document (covers its whole frame tree), an `allow` for every
 * subresource (the early requests allowAllRequests can miss, see
 * buildSitesDisabledRules) and a session allow for requests without a tab.
 * They replace every other Bastion dynamic/session rule while the switch is
 * off.
 */
export function buildGlobalOffRules(): SiteRules {
  return {
    dynamic: [
      {
        id: RULE_ID.SITES_DISABLED,
        priority: PRIORITY.SITE_DISABLED,
        action: { type: 'allowAllRequests' },
        condition: { resourceTypes: ['main_frame'] },
      },
      { id: RULE_ID.SITES_DISABLED_TOP, priority: PRIORITY.SITE_DISABLED, action: { type: 'allow' }, condition: {} },
    ],
    session: [
      {
        id: RULE_ID.SESSION_SITES_DISABLED_NO_TAB,
        priority: PRIORITY.SITE_DISABLED,
        action: { type: 'allow' },
        condition: { tabIds: [-1] },
      },
    ],
  };
}

export function isUnsafeRule(rule: DnrRule): boolean {
  return rule.action.type === 'redirect' || rule.action.type === 'modifyHeaders';
}

export function isRegexRule(rule: DnrRule): boolean {
  return typeof rule.condition.regexFilter === 'string';
}

/**
 * Remove conditions the running browser does not understand. Rules that
 * depend on `topDomains` are dropped entirely (they would otherwise apply
 * everywhere); `excludedTopDomains` is merely stripped (uBOL does the same).
 */
export function adaptRuleToBrowser(rule: DnrRule, topDomainsSupported: boolean): DnrRule | null {
  if (topDomainsSupported) return rule;
  if (rule.condition.topDomains) return null;
  if (rule.condition.excludedTopDomains) {
    const condition = { ...rule.condition };
    delete condition.excludedTopDomains;
    return { ...rule, condition };
  }
  return rule;
}

export interface RuleSource {
  /** For error reporting: 'system' | 'admin' | 'user' | 'debounce'. */
  name: string;
  rules: DnrRule[];
  /** First id for rules without an id; rules keep their id when set. */
  idStart?: number;
  idEnd?: number;
}

export interface PlannedRules {
  rules: DnrRule[];
  /** source name -> number of rules dropped and why. */
  dropped: { source: string; count: number; reason: string }[];
}

export interface RuleBudget {
  maxRules: number;
  maxUnsafe: number;
  maxRegex: number;
}

export const DYNAMIC_BUDGET: RuleBudget = {
  maxRules: LIMITS.MAX_DYNAMIC_RULES,
  maxUnsafe: LIMITS.MAX_UNSAFE_DYNAMIC_RULES,
  maxRegex: LIMITS.MAX_DYNAMIC_SESSION_REGEX_RULES,
};

/**
 * Assign ids and enforce the dynamic budgets (total, unsafe, regex) in source
 * order, so system rules always fit before admin, debounce and user rules.
 * `regexReserved` accounts for regex rules elsewhere in the shared
 * dynamic+session budget.
 */
export function planRules(sources: readonly RuleSource[], budget: RuleBudget, regexReserved = 0): PlannedRules {
  const out: DnrRule[] = [];
  const dropped: PlannedRules['dropped'] = [];
  let unsafe = 0;
  let regex = regexReserved;
  const usedIds = new Set<number>();
  for (const src of sources) {
    let nextId = src.idStart ?? 1;
    const idEnd = src.idEnd ?? Number.MAX_SAFE_INTEGER;
    const counts = new Map<string, number>();
    const drop = (reason: string) => counts.set(reason, (counts.get(reason) ?? 0) + 1);
    for (const r of src.rules) {
      if (out.length >= budget.maxRules) {
        drop('dynamic rule limit');
        continue;
      }
      const u = isUnsafeRule(r);
      if (u && unsafe >= budget.maxUnsafe) {
        drop('redirect/modifyHeaders rule limit');
        continue;
      }
      const rx = isRegexRule(r);
      if (rx && regex >= budget.maxRegex) {
        drop('regex rule limit');
        continue;
      }
      let id = r.id;
      if (id === undefined) {
        while (usedIds.has(nextId)) nextId++;
        if (nextId > idEnd) {
          drop('id range exhausted');
          continue;
        }
        id = nextId++;
      } else if (usedIds.has(id)) {
        drop('duplicate id');
        continue;
      }
      usedIds.add(id);
      if (u) unsafe++;
      if (rx) regex++;
      out.push({ ...r, id, priority: r.priority ?? 1 });
    }
    for (const [reason, count] of counts) dropped.push({ source: src.name, count, reason });
  }
  return { rules: out, dropped };
}

export interface RuleDiff {
  removeRuleIds: number[];
  addRules: DnrRule[];
}

/** Minimal atomic update from `current` to `desired` (rules compared structurally). */
export function diffRules(current: readonly DnrRule[], desired: readonly DnrRule[]): RuleDiff {
  const cur = new Map<number, string>();
  for (const r of current) if (typeof r.id === 'number') cur.set(r.id, canonicalJson(normalizeRuleForCompare(r)));
  const want = new Set<number>();
  const addRules: DnrRule[] = [];
  const removeRuleIds: number[] = [];
  for (const r of desired) {
    const id = r.id as number;
    want.add(id);
    const have = cur.get(id);
    if (have !== undefined && have === canonicalJson(normalizeRuleForCompare(r))) continue;
    if (have !== undefined) removeRuleIds.push(id);
    addRules.push(r);
  }
  for (const id of cur.keys()) if (!want.has(id)) removeRuleIds.push(id);
  removeRuleIds.sort((a, b) => a - b);
  return { removeRuleIds, addRules };
}

/** Chrome echoes rules with defaults filled in; compare on the meaningful parts only. */
function normalizeRuleForCompare(r: DnrRule): unknown {
  const condition: Record<string, unknown> = { ...r.condition };
  if (condition.isUrlFilterCaseSensitive === false) delete condition.isUrlFilterCaseSensitive;
  for (const [k, v] of Object.entries(condition)) {
    // Order of domain/type lists is not significant; arrays of objects
    // (responseHeaders) are compared as-is.
    if (Array.isArray(v) && v.every((x) => typeof x === 'string' || typeof x === 'number')) {
      condition[k] = [...v].sort();
    }
  }
  return { id: r.id, priority: r.priority ?? 1, action: r.action, condition };
}

/**
 * All dynamic rules Bastion manages itself (everything except custom filters
 * and debounce). With `globallyDisabled` (fleet kill switch) only the
 * global allow rules remain.
 */
export function buildSystemDynamicRules(
  settings: Settings,
  sites: SitesMap,
  opts: { topDomainsSupported: boolean; resourceTypes: readonly string[]; globallyDisabled?: boolean },
): { dynamic: DnrRule[]; session: DnrRule[] } {
  if (opts.globallyDisabled) return buildGlobalOffRules();
  const disabled = buildSitesDisabledRules(sites, opts.topDomainsSupported);
  const dynamic = [...disabled.dynamic, ...buildStandardModeRules(sites, settings.defaultMode, opts.topDomainsSupported)];
  if (settings.privacy.gpc) dynamic.push(buildGpcRule(opts.resourceTypes));
  return { dynamic, session: disabled.session };
}

/** Moved to shared/constants.ts so the popup can use it without background code. */
export { isSystemAllowRuleId } from '../shared/constants.ts';
