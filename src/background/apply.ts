// Bastion Shield service worker — the single idempotent applyAll()
// (ARCHITECTURE §10): brings the browser state in line with the effective
// configuration. Every step is independent and failure-tolerant: a problem in
// one step is logged and reported, never allowed to stop the others.
//
//   1. content-script registrations (cosmetic, generic-high CSS, scriptlets,
//      privacy). First, because Chrome drops dynamic registrations on every
//      extension update: pages loaded before this step get no cosmetics,
//      scriptlets or fingerprinting protection. The steps are independent.
//   2. enabled static rulesets (with budget checks and per-list fallback)
//   3. dynamic rules (sites off, Standard mode, GPC, custom, debounce)
//   4. session rules (no-tab allow for sites off; proceed rules are kept)
//   5. chrome.privacy settings
//   6. badge
//   7. content settings for blocked scripts
//
// Fleet kill switch (policy protectionEnabled: false): the dynamic and
// session rules become a global allow, every registration is removed and
// every chrome.privacy / content setting we control is released. Static
// rulesets stay enabled (the allow outranks them), so restoring is instant.
//
// In an incognito (split mode) instance chrome.privacy and contentSettings
// are left to the regular instance: their regular-scope settings cannot be
// changed from incognito and are inherited by it.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { MY_LISTS, RULE_ID } from '../shared/constants.ts';
import type { BuildMeta, CustomState, Settings, SitesMap } from '../shared/types.ts';
import type { DnrRule } from '../compiler/types.ts';
import type { ActivityService, BadgeMode } from './activity.ts';
import type { CustomCompiled } from './custom.ts';
import { loadCosmeticMeta, loadDebounceList, loadScriptletIndex } from './data.ts';
import { convertDebounceRules } from './debounce.ts';
import * as log from './log.ts';
import { applyPrivacySettings, applyScriptSettings } from './privacy-api.ts';
import { computeRegistrations, diffRegistrations, GENERIC_HIGH_ID_PREFIX } from './registrations.ts';
import type { DesiredScript, RegisteredScript } from './registrations.ts';
import { adaptRuleToBrowser, buildSystemDynamicRules, diffRules, DYNAMIC_BUDGET, FALLBACK_RESOURCE_TYPES, planRules } from './rules.ts';
import type { RuleSource } from './rules.ts';
import { countRules, LIST_ERROR, planRulesets, wantedRulesets } from './rulesets.ts';
import { isProceedRuleId } from './blocked.ts';
import { isBisectRuleId } from '../shared/bisect.ts';
import { explicitField, layerScopes } from './sites.ts';
import { canonicalJson, createDebouncedRunner, errMsg } from './util.ts';

export const BADGE_COLOR = '#2A3134';
const SESSION_REPORT_KEY = 'applied:report';
const SESSION_DISABLED_KEY = 'applied:disabled';
export const SESSION_APPLIED_KEY = 'applied:marker';

export interface ApplyReport {
  at: number;
  listErrors: Record<string, string>;
  /** Errors to show next to the custom-filter editor (dropped or invalid rules). */
  customErrors: CustomState['report']['errors'];
  adminErrors: CustomState['report']['errors'];
  /** Imported list id -> rules dropped or rejected by the browser. */
  myListErrors: Record<string, CustomState['report']['errors']>;
  problems: string[];
  budget: { used: number; available: number | null; regexUsed: number };
}

export function emptyReport(): ApplyReport {
  return { at: 0, listErrors: {}, customErrors: [], adminErrors: [], myListErrors: {}, problems: [], budget: { used: 0, available: null, regexUsed: 0 } };
}

export interface ApplyDeps {
  settings(): Settings;
  sites(): SitesMap;
  meta(): BuildMeta | null;
  custom(): CustomCompiled;
  seedFiles(): Promise<string[]>;
  activity: ActivityService;
  invalidateCosmetic(): void;
  /** Add/remove the activity listeners to match the settings. */
  syncListeners(): void;
  /** Fleet kill switch: policy protectionEnabled === false. */
  globallyDisabled(): boolean;
  /** Running in the incognito (split mode) instance. */
  incognito?: boolean;
}

// ---------------------------------------------------------------------------
// Feature detection
// ---------------------------------------------------------------------------

export function topDomainsSupported(): boolean {
  try {
    const keys = (chrome.declarativeNetRequest as unknown as { RuleConditionKeys?: Record<string, string> }).RuleConditionKeys;
    return !!keys && Object.values(keys).includes('topDomains');
  } catch {
    return false;
  }
}

export function browserResourceTypes(): string[] {
  try {
    const rt = (chrome.declarativeNetRequest as unknown as { ResourceType?: Record<string, string> }).ResourceType;
    const values = rt ? Object.values(rt).filter((v) => typeof v === 'string') : [];
    return values.length > 0 ? values : FALLBACK_RESOURCE_TYPES;
  } catch {
    return FALLBACK_RESOURCE_TYPES;
  }
}

export function badgeModeFor(settings: Settings): BadgeMode {
  if (!settings.ui.badge) return 'off';
  // Chromium counts every matched non-allow action, including our Sec-GPC
  // modifyHeaders rule, so with GPC on the built-in counter would count every
  // request. We maintain the badge ourselves in that case.
  return settings.privacy.gpc ? 'self' : 'browser';
}

function manifestRulesetOrder(): string[] {
  try {
    const m = chrome.runtime.getManifest() as { declarative_net_request?: { rule_resources?: { id: string }[] } };
    return (m.declarative_net_request?.rule_resources ?? []).map((r) => r.id).filter((id) => typeof id === 'string');
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Regex validation (dynamic rules must never contain an unsupported regex:
// one bad rule makes the whole atomic updateDynamicRules call fail)
// ---------------------------------------------------------------------------

const regexCache = new Map<string, string | null>();

async function regexProblem(rule: DnrRule): Promise<string | null> {
  const regex = rule.condition.regexFilter;
  if (typeof regex !== 'string') return null;
  const isCaseSensitive = rule.condition.isUrlFilterCaseSensitive === true;
  const requireCapturing = typeof rule.action.redirect?.regexSubstitution === 'string';
  const key = `${isCaseSensitive ? 1 : 0}${requireCapturing ? 1 : 0}${regex}`;
  if (regexCache.has(key)) return regexCache.get(key) ?? null;
  let problem: string | null = null;
  try {
    const fn = chrome.declarativeNetRequest.isRegexSupported;
    if (typeof fn === 'function') {
      const r = await fn({ regex, isCaseSensitive, requireCapturing });
      if (!r.isSupported) problem = r.reason ?? 'unsupported regex';
    }
  } catch (e) {
    problem = errMsg(e);
  }
  regexCache.set(key, problem);
  return problem;
}

async function dropInvalidRegex(rules: DnrRule[], onDrop: (rule: DnrRule, reason: string) => void): Promise<DnrRule[]> {
  const out: DnrRule[] = [];
  for (const r of rules) {
    const p = await regexProblem(r);
    if (p) onDrop(r, p);
    else out.push(r);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Debounce rules (constant per release, converted once per SW lifetime)
// ---------------------------------------------------------------------------

const debounceCache = new Map<boolean, DnrRule[]>();

async function debounceRules(deAmp: boolean): Promise<DnrRule[]> {
  const cached = debounceCache.get(deAmp);
  if (cached) return cached;
  const data = await loadDebounceList();
  if (!data) {
    log.warn('debounce', 'data/debounce.json missing or invalid; bounce-tracking protection inactive');
    return [];
  }
  const conv = convertDebounceRules(data, chrome.runtime.getURL('pages/bounce.html'), { deAmp });
  const rules = await dropInvalidRegex(conv.rules, (r, reason) => log.warn('debounce', r.condition.regexFilter, reason));
  debounceCache.set(deAmp, rules);
  return rules;
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

async function applyRulesets(settings: Settings, meta: BuildMeta | null, report: ApplyReport): Promise<void> {
  const dnr = chrome.declarativeNetRequest;
  const order = manifestRulesetOrder();
  const { candidates, missing } = wantedRulesets(meta, settings, order);
  Object.assign(report.listErrors, missing);
  const current = await log.attempt('rulesets', () => dnr.getEnabledRulesets(), [] as string[]);
  const available = await log.attempt('rulesets', () => dnr.getAvailableStaticRuleCount(), null as number | null);
  const currentCount = countRules(meta, current).rules;
  const budget = available === null ? Number.MAX_SAFE_INTEGER : currentCount + available;
  const plan = planRulesets(candidates, budget);
  Object.assign(report.listErrors, plan.errors);
  report.budget = { used: plan.usedRules, available, regexUsed: plan.usedRegex };

  const want = new Set(plan.enabled);
  const known = new Set(order.length > 0 ? order : [...current, ...plan.enabled]);
  const enableRulesetIds = plan.enabled.filter((id) => !current.includes(id));
  const disableRulesetIds = current.filter((id) => !want.has(id) && known.has(id));
  if (enableRulesetIds.length === 0 && disableRulesetIds.length === 0) return;
  try {
    await dnr.updateEnabledRulesets({ enableRulesetIds, disableRulesetIds });
    return;
  } catch (e) {
    log.warn('rulesets', 'batch update failed, retrying per list', e);
  }
  // Fallback: disable first (cannot fail for budget reasons), then enable list by list.
  if (disableRulesetIds.length > 0) await log.attempt('rulesets', () => dnr.updateEnabledRulesets({ disableRulesetIds }));
  const byList = new Map<string, string[]>();
  for (const c of candidates) {
    if (!enableRulesetIds.includes(c.rulesetId)) continue;
    const arr = byList.get(c.listId) ?? [];
    arr.push(c.rulesetId);
    byList.set(c.listId, arr);
  }
  for (const [listId, ids] of byList) {
    try {
      await dnr.updateEnabledRulesets({ enableRulesetIds: ids });
      continue;
    } catch (e) {
      const main = ids.filter((id) => !id.endsWith('.regex'));
      if (main.length > 0 && main.length < ids.length) {
        // Keep the list; give up only its regex companion.
        try {
          await dnr.updateEnabledRulesets({ enableRulesetIds: main });
          report.listErrors[listId] = LIST_ERROR.REGEX_LIMIT;
          continue;
        } catch {
          /* fall through */
        }
      }
      report.listErrors[listId] = errMsg(e);
      log.error('rulesets', listId, e);
    }
  }
  const final = await log.attempt('rulesets', () => dnr.getEnabledRulesets(), [] as string[]);
  const used = countRules(meta, final);
  report.budget.used = used.rules;
  report.budget.regexUsed = used.regex;
}

interface DynamicPlan {
  dynamic: DnrRule[];
  session: DnrRule[];
}

async function buildDynamic(deps: ApplyDeps, report: ApplyReport): Promise<DynamicPlan> {
  const settings = deps.settings();
  const sites = deps.sites();
  const top = topDomainsSupported();
  const off = deps.globallyDisabled();
  const system = buildSystemDynamicRules(settings, sites, { topDomainsSupported: top, resourceTypes: browserResourceTypes(), globallyDisabled: off });
  // Kill switch: nothing but the global allow (no custom filters, debounce or GPC).
  if (off) return { dynamic: planRules([{ name: 'system', rules: system.dynamic }], DYNAMIC_BUDGET).rules, session: system.session };
  const custom = deps.custom();
  const adapt = (rules: readonly DnrRule[]): DnrRule[] =>
    rules
      .map((r) => adaptRuleToBrowser({ ...r, id: undefined }, top))
      .filter((r): r is DnrRule => r !== null);
  const customDrop = (target: ApplyReport['customErrors']) => (r: DnrRule, reason: string) =>
    target.push({ line: 0, text: r.condition.regexFilter ?? '', reason: `regex not supported by the browser: ${reason}` });
  const admin = await dropInvalidRegex(adapt(custom.admin.rules), customDrop(report.adminErrors));
  const user = await dropInvalidRegex(adapt(custom.user.rules), customDrop(report.customErrors));
  const myErrors = (id: string): ApplyReport['customErrors'] => (report.myListErrors[id] ??= []);
  const my: RuleSource[] = [];
  for (const m of custom.my) {
    const start = RULE_ID.MY_LISTS_START + m.slot * MY_LISTS.SLOT_SIZE;
    my.push({ name: `my:${m.id}`, rules: await dropInvalidRegex(adapt(m.compiled.rules), customDrop(myErrors(m.id))), idStart: start, idEnd: start + MY_LISTS.SLOT_SIZE - 1 });
  }
  const debounce = settings.privacy.debounce ? await debounceRules(settings.privacy.deAmp) : [];
  const sources: RuleSource[] = [
    { name: 'system', rules: system.dynamic },
    { name: 'admin', rules: admin, idStart: RULE_ID.ADMIN_START, idEnd: RULE_ID.ADMIN_END },
    { name: 'debounce', rules: debounce, idStart: RULE_ID.DEBOUNCE_START, idEnd: RULE_ID.DEBOUNCE_END },
    { name: 'user', rules: user, idStart: RULE_ID.CUSTOM_START, idEnd: RULE_ID.CUSTOM_END },
    // Imported lists come last: the user's own filters always fit first.
    ...my,
  ];
  const sessionRegex = system.session.filter((r) => typeof r.condition.regexFilter === 'string').length;
  const plan = planRules(sources, DYNAMIC_BUDGET, sessionRegex);
  for (const d of plan.dropped) {
    const msg = { line: 0, text: '', reason: `${d.count} rule(s) not applied: ${d.reason}` };
    if (d.source === 'user') report.customErrors.push(msg);
    else if (d.source === 'admin') report.adminErrors.push(msg);
    else if (d.source.startsWith('my:')) myErrors(d.source.slice(3)).push(msg);
    else report.problems.push(`${d.source}: ${msg.reason}`);
  }
  return { dynamic: plan.rules, session: system.session };
}

/** Rule id mentioned in a DNR error message ("Rule with id 12 ..."), if any. */
export function ruleIdFromError(message: string): number | null {
  const m = /\bid\s+(\d+)/i.exec(message);
  return m ? Number(m[1]) : null;
}

/** Imported list id owning a dynamic rule id, from its slot (custom.my lists the slots). */
function myListOfRule(ruleId: number, my: CustomCompiled['my']): string | null {
  if (ruleId < RULE_ID.MY_LISTS_START || ruleId > RULE_ID.MY_LISTS_END) return null;
  const slot = Math.floor((ruleId - RULE_ID.MY_LISTS_START) / MY_LISTS.SLOT_SIZE);
  return my.find((m) => m.slot === slot)?.id ?? null;
}

async function applyDynamic(plan: DynamicPlan, report: ApplyReport, my: CustomCompiled['my'] = []): Promise<void> {
  const dnr = chrome.declarativeNetRequest;
  const current = (await log.attempt('dynamic', () => dnr.getDynamicRules(), [] as chrome.declarativeNetRequest.Rule[])) as unknown as DnrRule[];
  let desired = plan.dynamic;
  const isSystem = (id: number) => id >= RULE_ID.SITES_DISABLED && id <= RULE_ID.SYSTEM_DYNAMIC_END;
  // Tiers to fall back to if Chrome rejects the update: drop offending
  // rules first, then whole sources, keeping the system rules to the end.
  for (let attempt = 0; attempt < 8; attempt++) {
    const diff = diffRules(current, desired);
    if (diff.addRules.length === 0 && diff.removeRuleIds.length === 0) return;
    try {
      await dnr.updateDynamicRules({ removeRuleIds: diff.removeRuleIds, addRules: diff.addRules as chrome.declarativeNetRequest.Rule[] });
      return;
    } catch (e) {
      const msg = errMsg(e);
      log.error('dynamic', msg);
      const badId = ruleIdFromError(msg);
      if (badId !== null && desired.some((r) => r.id === badId) && !isSystem(badId)) {
        const bad = desired.find((r) => r.id === badId);
        const entry = { line: 0, text: bad?.condition.urlFilter ?? bad?.condition.regexFilter ?? '', reason: msg };
        const myId = myListOfRule(badId, my);
        if (myId !== null) (report.myListErrors[myId] ??= []).push(entry);
        else if (badId >= RULE_ID.ADMIN_START && badId <= RULE_ID.ADMIN_END) report.adminErrors.push(entry);
        else if (badId <= RULE_ID.CUSTOM_END) report.customErrors.push(entry);
        else report.problems.push(`dynamic: ${msg}`);
        desired = desired.filter((r) => r.id !== badId);
        continue;
      }
      const inRange = (r: DnrRule, a: number, b: number) => (r.id as number) >= a && (r.id as number) <= b;
      if (desired.some((r) => inRange(r, RULE_ID.MY_LISTS_START, RULE_ID.MY_LISTS_END))) {
        for (const m of my) (report.myListErrors[m.id] ??= []).push({ line: 0, text: '', reason: `list not applied: ${msg}` });
        desired = desired.filter((r) => !inRange(r, RULE_ID.MY_LISTS_START, RULE_ID.MY_LISTS_END));
      } else if (desired.some((r) => inRange(r, RULE_ID.CUSTOM_START, RULE_ID.CUSTOM_END))) {
        report.customErrors.push({ line: 0, text: '', reason: `custom filters not applied: ${msg}` });
        desired = desired.filter((r) => !inRange(r, RULE_ID.CUSTOM_START, RULE_ID.CUSTOM_END));
      } else if (desired.some((r) => inRange(r, RULE_ID.DEBOUNCE_START, RULE_ID.DEBOUNCE_END))) {
        report.problems.push(`debounce rules not applied: ${msg}`);
        desired = desired.filter((r) => !inRange(r, RULE_ID.DEBOUNCE_START, RULE_ID.DEBOUNCE_END));
      } else if (desired.some((r) => inRange(r, RULE_ID.ADMIN_START, RULE_ID.ADMIN_END))) {
        report.adminErrors.push({ line: 0, text: '', reason: `admin filters not applied: ${msg}` });
        desired = desired.filter((r) => !inRange(r, RULE_ID.ADMIN_START, RULE_ID.ADMIN_END));
      } else {
        report.problems.push(`dynamic rules: ${msg}`);
        return;
      }
    }
  }
}

async function applySession(plan: DynamicPlan, reason: string, report: ApplyReport): Promise<void> {
  const dnr = chrome.declarativeNetRequest;
  const current = (await log.attempt('session', () => dnr.getSessionRules(), [] as chrome.declarativeNetRequest.Rule[])) as unknown as DnrRule[];
  // Proceed-anyway and bisect rules belong to live tabs; keep them except on a
  // fresh install. Bisect state lives in storage.session, which an update
  // clears, so its rules go then too.
  const keep = current.filter(
    (r) => reason !== 'install' && (isProceedRuleId(r.id as number) || (isBisectRuleId(r.id as number) && reason !== 'update')),
  );
  const managed = current.filter((r) => !keep.includes(r));
  const diff = diffRules(managed, plan.session);
  if (diff.addRules.length === 0 && diff.removeRuleIds.length === 0) return;
  try {
    await dnr.updateSessionRules({ removeRuleIds: diff.removeRuleIds, addRules: diff.addRules as chrome.declarativeNetRequest.Rule[] });
  } catch (e) {
    report.problems.push(`session rules: ${errMsg(e)}`);
    log.error('session', e);
  }
}

function toChromeScript(d: DesiredScript): chrome.scripting.RegisteredContentScript {
  const s: Record<string, unknown> = {
    id: d.id,
    matches: d.matches,
    runAt: d.runAt,
    allFrames: d.allFrames,
    matchOriginAsFallback: d.matchOriginAsFallback,
    persistAcrossSessions: d.persistAcrossSessions,
    world: d.world,
  };
  if (d.js) s.js = d.js;
  if (d.css) s.css = d.css;
  if (d.excludeMatches && d.excludeMatches.length > 0) s.excludeMatches = d.excludeMatches;
  return s as unknown as chrome.scripting.RegisteredContentScript;
}

async function applyRegistrations(deps: ApplyDeps, report: ApplyReport): Promise<void> {
  const scripting = chrome.scripting;
  if (deps.globallyDisabled()) {
    // Every dynamic registration of this extension is ours.
    const registered = await log.attempt('scripts', () => scripting.getRegisteredContentScripts(), [] as chrome.scripting.RegisteredContentScript[]);
    const ids = registered.map((r) => r.id);
    if (ids.length > 0) await log.attempt('scripts', () => scripting.unregisterContentScripts({ ids }));
    return;
  }
  const settings = deps.settings();
  const meta = deps.meta();
  const enabledLists = (meta?.lists ?? []).filter((l) => settings.lists[l.id]);
  const enabledListIds = new Set(enabledLists.map((l) => l.id));
  const softListIds = new Set(enabledLists.filter((l) => l.firstPartyProtected).map((l) => l.id));
  const [cosmeticMeta, scriptletIndex, seedFiles] = await Promise.all([loadCosmeticMeta(), loadScriptletIndex(), deps.seedFiles()]);
  const desired = computeRegistrations({
    settings,
    sites: deps.sites(),
    enabledListIds,
    cosmeticMeta,
    scriptletIndex,
    seedFiles,
    extraGenericHideHosts: deps.custom().genericHideHosts,
    softListIds,
  });
  const current = (await log.attempt('scripts', () => scripting.getRegisteredContentScripts(), [] as chrome.scripting.RegisteredContentScript[])) as unknown as RegisteredScript[];
  const diff = diffRegistrations(current, desired);
  // A data file that failed to load must not unregister what it describes.
  const keep = (id: string) =>
    (scriptletIndex === null && id.startsWith('sl-')) || (cosmeticMeta === null && id.startsWith(GENERIC_HIGH_ID_PREFIX));
  if (scriptletIndex === null) report.problems.push('scriptlets/index.json unavailable');
  if (cosmeticMeta === null) report.problems.push('cosmetic/meta.json unavailable');
  diff.unregister = diff.unregister.filter((id) => !keep(id) || desired.some((d) => d.id === id));
  if (diff.unregister.length > 0) {
    await log.attempt('scripts', () => scripting.unregisterContentScripts({ ids: diff.unregister }));
  }
  if (diff.update.length > 0) {
    try {
      await scripting.updateContentScripts(diff.update.map(toChromeScript));
    } catch (e) {
      log.warn('scripts', 'update failed, re-registering', e);
      await log.attempt('scripts', () => scripting.unregisterContentScripts({ ids: diff.update.map((d) => d.id) }));
      diff.register.push(...diff.update);
    }
  }
  if (diff.register.length > 0) {
    try {
      await scripting.registerContentScripts(diff.register.map(toChromeScript));
    } catch (e) {
      // All-or-nothing: isolate the offending registration(s).
      log.warn('scripts', 'batch register failed, retrying one by one', e);
      for (const d of diff.register) {
        try {
          await scripting.registerContentScripts([toChromeScript(d)]);
        } catch (err) {
          report.problems.push(`script ${d.id}: ${errMsg(err)}`);
          log.error('scripts', d.id, err);
        }
      }
    }
  }
}

const SESSION_BADGE_KEY = 'applied:badgeMode';

async function applyBadge(settings: Settings, activity: ActivityService): Promise<void> {
  const mode = badgeModeFor(settings);
  await log.attempt('badge', () => chrome.declarativeNetRequest.setExtensionActionOptions({ displayActionCountAsBadgeText: mode === 'browser' }));
  await log.attempt('badge', () => chrome.action.setBadgeBackgroundColor({ color: BADGE_COLOR }));
  await log.attempt('badge', () => chrome.action.setBadgeTextColor?.({ color: '#FFFFFF' }));
  const got = await log.attempt('badge', () => chrome.storage.session.get(SESSION_BADGE_KEY), {} as Record<string, unknown>);
  if (got[SESSION_BADGE_KEY] === 'self' && mode !== 'self') {
    // Tab-specific texts we set would otherwise hide the browser's counter
    // until the tab closes, also for tabs this worker instance never saw.
    const tabs = await log.attempt('badge', () => chrome.tabs.query({}), [] as chrome.tabs.Tab[]);
    for (const t of tabs) {
      const tabId = t.id;
      if (typeof tabId === 'number') await log.attempt('badge', () => chrome.action.setBadgeText({ tabId, text: null as unknown as string }));
    }
  }
  if (got[SESSION_BADGE_KEY] !== mode) await log.attempt('badge', () => chrome.storage.session.set({ [SESSION_BADGE_KEY]: mode }));
  activity.setBadgeMode(mode);
}

/** Disabled-site fingerprint, used to refresh per-tab icons only when it changes. */
export function disabledFingerprint(sites: SitesMap, globallyDisabled = false): string {
  if (globallyDisabled) return '"all"';
  return canonicalJson(layerScopes(explicitField(sites, 'enabled'), true).filter((g) => !g.value));
}

export interface Applier {
  /** Debounced (300 ms) applyAll; resolves after a run that includes the latest state. */
  schedule(): Promise<void>;
  /** applyAll without the debounce delay. */
  now(reason?: string): Promise<void>;
  report(): ApplyReport;
  /** Restore the last report after a service worker restart. */
  restoreReport(): Promise<void>;
}

export function createApplier(deps: ApplyDeps, onSitesDisabledChanged: () => void): Applier {
  let lastReport: ApplyReport = emptyReport();
  let reason = 'change';
  let lastDisabled: string | null = null;

  const run = async (): Promise<void> => {
    const why = reason;
    reason = 'change';
    const report = emptyReport();
    report.at = Date.now();
    const settings = deps.settings();
    const meta = deps.meta();
    const step = async (name: string, fn: () => Promise<void>) => {
      try {
        await fn();
      } catch (e) {
        report.problems.push(`${name}: ${errMsg(e)}`);
        log.error('apply', name, e);
      }
    };
    const off = deps.globallyDisabled();
    // Without build metadata we cannot tell lists apart: keep the manifest
    // defaults and existing registrations rather than switching filtering off
    // (the kill switch still removes the registrations).
    if (meta || off) await step('scripts', () => applyRegistrations(deps, report));
    if (meta) await step('rulesets', () => applyRulesets(settings, meta, report));
    else report.problems.push('rulesets/meta.json unavailable: rulesets and scripts left as they are');
    let plan: DynamicPlan = { dynamic: [], session: [] };
    await step('dynamic-plan', async () => {
      plan = await buildDynamic(deps, report);
    });
    await step('dynamic', () => applyDynamic(plan, report, off ? [] : deps.custom().my));
    await step('session', () => applySession(plan, why, report));
    if (!deps.incognito) {
      await step('privacy', async () => {
        report.problems.push(...(await applyPrivacySettings(settings, off)));
      });
    }
    await step('badge', () => applyBadge(settings, deps.activity));
    if (!deps.incognito) await step('contentSettings', () => applyScriptSettings(off ? {} : deps.sites()));
    deps.invalidateCosmetic();
    deps.syncListeners();
    const fp = disabledFingerprint(deps.sites(), off);
    // Icons of open tabs only need a refresh when the set of sites with
    // protection off changed (or on the first run of a browser session).
    if (fp !== lastDisabled) onSitesDisabledChanged();
    lastDisabled = fp;
    lastReport = report;
    await log.attempt('apply', () =>
      chrome.storage.session.set({
        [SESSION_REPORT_KEY]: report,
        [SESSION_DISABLED_KEY]: fp,
        [SESSION_APPLIED_KEY]: { at: report.at, version: chrome.runtime.getManifest().version },
      }),
    );
    if (report.problems.length > 0) log.warn('apply', report.problems);
  };

  const runner = createDebouncedRunner(run, 300, (e) => log.error('apply', e));

  // A pending run keeps the most significant reason (install clears proceed rules).
  const rank: Record<string, number> = { change: 0, startup: 1, update: 2, install: 3 };
  return {
    schedule: () => runner.schedule(),
    now: (why = 'change') => {
      if ((rank[why] ?? 0) > (rank[reason] ?? 0)) reason = why;
      return runner.now();
    },
    report: () => lastReport,
    async restoreReport() {
      const got = await log.attempt('apply', () => chrome.storage.session.get([SESSION_REPORT_KEY, SESSION_DISABLED_KEY]), {} as Record<string, unknown>);
      const r = got[SESSION_REPORT_KEY] as ApplyReport | undefined;
      if (r && typeof r === 'object' && typeof r.at === 'number') lastReport = { ...emptyReport(), ...r };
      const fp = got[SESSION_DISABLED_KEY];
      if (typeof fp === 'string') lastDisabled = fp;
    },
  };
}

