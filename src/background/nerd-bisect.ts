// Bastion Shield service worker — nerd mode filter bisect ("git bisect for
// broken sites", docs/NERD-MODE.md). The user opens the popup on a broken
// page and answers "does it work now?" after each test reload; the search
// itself is the pure machine in shared/bisect.ts.
//
// Each test is a handful of session `allow` rules (RULE_ID.SESSION_BISECT_*,
// PRIORITY.BISECT_ALLOW) with `requestDomains` = the hosts let through and
// `tabIds` = the tab, followed by a reload. `allow` does not lift cosmetic
// filters or scriptlets: a page broken by those ends in 'clean'.
//
// From 'clean' the user can go on with the cosmetic phase (action
// 'cosmetic'): the same machine over the enabled lists, where "let through"
// means "cosmetic filters of this list off on this tab" (cosmeticOverride,
// read by CosmeticService for every frame of the tab), then over the
// host-specific selectors of the culprit lists. Scriptlets and the
// registered generic-high CSS are not per tab and stay on.
//
// State is per tab in chrome.storage.session (survives service-worker
// restarts, not browser restarts or updates; apply.ts drops the rules on
// update). Rules are removed on finish, cancel, keep, tab close, navigation
// to another site (also the cosmetic override, which lives in the same
// record), and for tabs that no longer exist when state is first
// loaded after a restart, and for every tab when nerd mode is switched off.
// While a test runs, the tab's toolbar badge shows the step ("2/5"); the
// activity badge leaves that tab alone until the test phase ends
// (holdsBadge). Nothing here throws to the caller.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { DnrRule } from '../compiler/types.ts';
import { PRIORITY, RULE_ID } from '../shared/constants.ts';
import {
  allowConditions,
  answerBisect,
  badgeStep,
  bisectProgress,
  isBisectableHost,
  isBisectRuleId,
  keepCosmeticLines,
  keepFilterLines,
  MAX_CANDIDATES,
  startBisect,
} from '../shared/bisect.ts';
import type { BisectMachine } from '../shared/bisect.ts';
import type { BisectCandidate, BisectView, MsgNerdBisect, NerdBlockedHost } from '../shared/types.ts';
import type { TabCosmeticOverride } from './cosmetic.ts';
import * as log from './log.ts';
import { dayKey, errMsg, isPlainObject, webHostOf } from './util.ts';

export interface BisectDeps {
  /** Hosts blocked on the tab's current page load, with their rule attributions. */
  blockedOnTab(tabId: number): Promise<{ host: string; rule?: string; list?: string }[]>;
  /** Site key of the tab's top-level page. */
  siteOf(tabId: number): Promise<string | null>;
  /**
   * Filter texts for "rulesetId:ruleId" (transparency map), list ids, and
   * whether any of the rules is an $important block (also for dynamic rules,
   * which have no filter text here).
   */
  describeRules(rules: readonly string[]): Promise<{ filters: string[]; lists: string[]; important?: boolean }>;
  /** Append exception filters to the user's custom filters and apply them. Rejects with Error('locked') while policy makes them read-only. */
  addCustomFilters(lines: readonly string[]): Promise<void>;
  /** Tab badge: the step text while a test runs, null to hand the badge back to the normal counter. */
  badge?(tabId: number, text: string | null): void;
  /**
   * Cosmetic phase: the enabled lists with cosmetic filters, in test order
   * (CUSTOM_COSMETIC for the custom filters), and the host-specific selectors
   * each has in effect on the tab's page. Null without a web page.
   */
  cosmeticCandidates?(tabId: number): Promise<{ lists: string[]; selectors: Record<string, string[]> } | null>;
}

type Described = BisectCandidate & { filters: string[]; lists: string[]; important?: boolean };

/** The cosmetic phase (after a 'clean' network bisect). */
interface CosmeticBisect {
  stage: 'lists' | 'selectors';
  /** Over list ids: "allowed" lists have their cosmetic filters off on the tab. */
  lists: BisectMachine;
  /** Over the culprit lists' host-specific selectors: "allowed" ones are off. */
  selectors?: BisectMachine;
}

interface TabBisect {
  v: 1;
  tabId: number;
  site: string;
  candidates: BisectCandidate[];
  /** List ids the activity log attributed per host (used when a rule id is unknown). */
  lists: Record<string, string[]>;
  m: BisectMachine;
  /** Session rules installed for the current test. */
  ruleIds: number[];
  /** Described culprits once the machine reports 'found'. */
  culprits: Described[];
  /** Set once the user goes on with the cosmetic phase. */
  cos?: CosmeticBisect;
}

type Reply = { bisect: BisectView | null } | { hosts: NerdBlockedHost[] } | { added: string[] } | { error: string };

const KEY_PREFIX = 'nerd:bisect:';
/** Rule attributions kept per candidate (storage stays small). */
const MAX_RULES_PER_HOST = 16;

const keyOf = (tabId: number): string => `${KEY_PREFIX}${tabId}`;
const siteKey = (url: string): string | null => webHostOf(url)?.replace(/^www\./, '') ?? null;

/** Distinct bisectable hosts from the activity rows, most blocked requests first. */
export function collectCandidates(rows: readonly { host: string; rule?: string; list?: string }[]): {
  candidates: BisectCandidate[];
  lists: Record<string, string[]>;
} {
  const by = new Map<string, { rules: Set<string>; lists: Set<string>; count: number }>();
  for (const r of rows) {
    const host = typeof r?.host === 'string' ? r.host.toLowerCase().replace(/\.$/, '') : '';
    if (!isBisectableHost(host)) continue;
    let e = by.get(host);
    if (!e) by.set(host, (e = { rules: new Set(), lists: new Set(), count: 0 }));
    e.count++;
    if (typeof r.rule === 'string' && r.rule && e.rules.size < MAX_RULES_PER_HOST) e.rules.add(r.rule);
    if (typeof r.list === 'string' && r.list) e.lists.add(r.list);
  }
  const sorted = Array.from(by.entries())
    .sort((a, b) => b[1].count - a[1].count || a[0].localeCompare(b[0]))
    .slice(0, MAX_CANDIDATES);
  return {
    candidates: sorted.map(([host, e]) => ({ host, rules: Array.from(e.rules), count: e.count })),
    lists: Object.fromEntries(sorted.map(([host, e]) => [host, Array.from(e.lists)])),
  };
}

/** The machine the user is answering: the network one, or the cosmetic stage's. */
function activeMachine(rec: TabBisect): BisectMachine {
  const c = rec.cos;
  if (!c) return rec.m;
  return c.stage === 'selectors' && c.selectors ? c.selectors : c.lists;
}

/**
 * What the cosmetic phase switches off on the tab now: the lists under test,
 * the selectors under test, or the result (lists when no selector explains
 * it). Nothing once the lists alone did not help ('clean').
 */
export function cosmeticOverrideOf(c: CosmeticBisect | undefined): TabCosmeticOverride | null {
  if (!c) return null;
  if (c.stage === 'selectors' && c.selectors) {
    if (c.selectors.result === 'clean') return { lists: [...c.lists.culprits], selectors: [] };
    return c.selectors.allowed.length ? { lists: [], selectors: [...c.selectors.allowed] } : null;
  }
  return c.lists.allowed.length ? { lists: [...c.lists.allowed], selectors: [] } : null;
}

function cosmeticViewOf(rec: TabBisect, c: CosmeticBisect, phase?: BisectView['phase']): BisectView {
  const m = activeMachine(rec);
  const { step, maxSteps } = bisectProgress(m);
  // No host-specific selector explains it: the result is the lists.
  const listsOnly = c.stage === 'selectors' && m.result === 'clean';
  const p = phase ?? (listsOnly ? 'found' : m.result);
  let remaining = 0;
  if (p === 'found') remaining = listsOnly ? c.lists.culprits.length : m.culprits.length;
  else if (p === 'testing') remaining = m.test === 'all' ? m.hosts.length : m.test === 'half' ? m.suspects.length : m.pool.length;
  const ov = cosmeticOverrideOf(c);
  const v: BisectView = {
    tabId: rec.tabId,
    site: rec.site,
    phase: p,
    step,
    maxSteps,
    remaining,
    allowed: p === 'testing' || p === 'found' ? [...(ov?.lists ?? []), ...(ov?.selectors ?? [])] : [],
    kind: 'cosmetic',
    stage: c.stage,
  };
  if (p === 'found') {
    v.lists = [...c.lists.culprits];
    if (!listsOnly && c.stage === 'selectors') v.selectors = [...m.culprits];
    if (c.lists.partial || (!listsOnly && m.partial)) v.partial = true;
  }
  return v;
}

function viewOf(rec: TabBisect, phase?: BisectView['phase']): BisectView {
  if (rec.cos) return cosmeticViewOf(rec, rec.cos, phase);
  const m = rec.m;
  const { step, maxSteps } = bisectProgress(m);
  const p = phase ?? m.result;
  let remaining = 0;
  if (p === 'found') remaining = m.culprits.length;
  else if (p === 'testing') remaining = m.test === 'all' ? m.hosts.length : m.test === 'half' ? m.suspects.length : m.pool.length;
  const v: BisectView = {
    tabId: rec.tabId,
    site: rec.site,
    phase: p,
    step,
    maxSteps,
    remaining,
    allowed: p === 'testing' || p === 'found' ? [...m.allowed] : [],
  };
  if (p === 'found' && rec.culprits.length) {
    v.culprit = rec.culprits[0];
    if (rec.culprits.length > 1) v.also = rec.culprits.slice(1);
    if (m.partial) v.partial = true;
  }
  return v;
}

function isTabBisect(v: unknown): v is TabBisect {
  return (
    isPlainObject(v) &&
    v.v === 1 &&
    typeof v.tabId === 'number' &&
    typeof v.site === 'string' &&
    Array.isArray(v.candidates) &&
    isPlainObject(v.m) &&
    Array.isArray(v.m.hosts) &&
    Array.isArray(v.ruleIds) &&
    Array.isArray(v.culprits) &&
    (v.cos === undefined || (isPlainObject(v.cos) && isPlainObject(v.cos.lists) && Array.isArray(v.cos.lists.hosts)))
  );
}

const sessionRules = (): Promise<chrome.declarativeNetRequest.Rule[]> =>
  log.attempt('bisect', async () => (await chrome.declarativeNetRequest.getSessionRules()) ?? [], [] as chrome.declarativeNetRequest.Rule[]);

export class Bisector {
  private readonly deps: BisectDeps;
  private readonly tabs = new Map<number, TabBisect>();
  private loaded: Promise<void> | null = null;
  private queue: Promise<unknown> = Promise.resolve();
  /** Tabs whose badge shows a bisect step. */
  private readonly badged = new Set<number>();

  constructor(deps: BisectDeps) {
    this.deps = deps;
  }

  /** One operation at a time (double clicks, a reload commit racing an answer). */
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const p = this.queue.then(fn, fn);
    this.queue = p.catch(() => undefined);
    return p;
  }

  /** Restore state after a service-worker restart; drop what belongs to closed tabs or to nobody. */
  private ensureLoaded(): Promise<void> {
    this.loaded ??= (async () => {
      const all = await log.attempt('bisect', () => chrome.storage.session.get(null), {} as Record<string, unknown>);
      for (const [k, v] of Object.entries(all ?? {})) {
        if (!k.startsWith(KEY_PREFIX)) continue;
        if (!isTabBisect(v)) {
          await log.attempt('bisect', () => chrome.storage.session.remove(k));
          continue;
        }
        this.tabs.set(v.tabId, v);
        const alive = await chrome.tabs.get(v.tabId).then(
          (t) => !!t,
          () => false,
        );
        if (!alive) await this.drop(v.tabId, false);
        else this.syncBadge(v.tabId);
      }
      // Orphans: rules whose state is gone (storage cleared, crash between the two writes).
      const owned = new Set<number>();
      for (const r of this.tabs.values()) for (const id of r.ruleIds) owned.add(id);
      const orphans = (await sessionRules()).filter((r) => isBisectRuleId(r.id) && !owned.has(r.id)).map((r) => r.id);
      if (orphans.length) await log.attempt('bisect', () => chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: orphans }));
    })().catch((e: unknown) => log.warn('bisect', 'restore', e));
    return this.loaded;
  }

  private async save(rec: TabBisect): Promise<void> {
    this.tabs.set(rec.tabId, rec);
    await log.attempt('bisect', () => chrome.storage.session.set({ [keyOf(rec.tabId)]: rec }));
  }

  /** Remove the tab's rules (every bisect rule carries tabIds [tabId]) and state; reload back to normal protection when rules were in place. */
  private async drop(tabId: number, reload: boolean): Promise<TabBisect | undefined> {
    const rec = this.tabs.get(tabId);
    this.tabs.delete(tabId);
    const ids = (await sessionRules())
      .filter((r) => isBisectRuleId(r.id) && r.condition.tabIds?.includes(tabId) === true)
      .map((r) => r.id);
    if (ids.length) await log.attempt('bisect', () => chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids }));
    await log.attempt('bisect', () => chrome.storage.session.remove(keyOf(tabId)));
    const lifted = ids.length > 0 || (rec?.ruleIds.length ?? 0) > 0 || cosmeticOverrideOf(rec?.cos) !== null;
    if (reload && lifted) await log.attempt('bisect', () => chrome.tabs.reload(tabId));
    return rec;
  }

  /** Install the session rules for `rec.m.allowed` (replacing the tab's previous ones), then reload. Throws on DNR errors. */
  private async install(rec: TabBisect): Promise<void> {
    const current = (await chrome.declarativeNetRequest.getSessionRules()) ?? [];
    const existing = new Set(current.map((r) => r.id));
    const used = new Set(current.filter((r) => isBisectRuleId(r.id) && !rec.ruleIds.includes(r.id)).map((r) => r.id));
    const addRules: DnrRule[] = [];
    const ids: number[] = [];
    let id = RULE_ID.SESSION_BISECT_START;
    for (const c of allowConditions(rec.m.allowed, rec.m.hosts)) {
      while (used.has(id)) id++;
      if (id > RULE_ID.SESSION_BISECT_END) throw new Error('no free bisect rule ids');
      used.add(id);
      ids.push(id);
      // No resourceTypes: every type but main_frame, so the page itself is never touched.
      addRules.push({ id, priority: PRIORITY.BISECT_ALLOW, action: { type: 'allow' }, condition: { ...c, tabIds: [rec.tabId] } });
    }
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: rec.ruleIds.filter((x) => existing.has(x)),
      addRules: addRules as unknown as chrome.declarativeNetRequest.Rule[],
    });
    rec.ruleIds = ids;
    await log.attempt('bisect', () => chrome.tabs.reload(rec.tabId));
  }

  private async describeOne(c: BisectCandidate, lists: readonly string[]): Promise<Described> {
    const d = await this.deps.describeRules(c.rules).catch(() => ({ filters: [] as string[], lists: [] as string[], important: false }));
    const out: Described = { ...c, filters: d.filters, lists: Array.from(new Set([...d.lists, ...lists])) };
    if (d.important === true) out.important = true;
    return out;
  }

  private async describe(rec: TabBisect): Promise<Described[]> {
    const out: Described[] = [];
    for (const host of rec.m.culprits) {
      out.push(await this.describeOne(rec.candidates.find((x) => x.host === host) ?? { host, rules: [], count: 0 }, rec.lists[host] ?? []));
    }
    return out;
  }

  private async start(tabId: number): Promise<Reply> {
    const prev = this.tabs.get(tabId);
    if (prev && activeMachine(prev).result === 'testing') return { bisect: viewOf(prev) };
    if (prev) await this.drop(tabId, false);
    const site = await this.deps.siteOf(tabId);
    if (!site) return { error: 'no site' };
    const { candidates, lists } = collectCandidates(await this.deps.blockedOnTab(tabId));
    const rec: TabBisect = { v: 1, tabId, site, candidates, lists, m: startBisect(candidates.map((c) => c.host)), ruleIds: [], culprits: [] };
    if (rec.m.result === 'testing') await this.install(rec);
    await this.save(rec);
    return { bisect: viewOf(rec) };
  }

  private async answer(tabId: number, works: unknown): Promise<Reply> {
    const prev = this.tabs.get(tabId);
    if (prev?.cos) return this.answerCosmetic(prev, prev.cos, works);
    if (!prev || prev.m.result !== 'testing') return { error: 'not testing' };
    if (typeof works !== 'boolean') return { error: 'invalid answer' };
    const rec: TabBisect = { ...prev, m: answerBisect(prev.m, works) };
    if (rec.m.result === 'clean') {
      // Back to normal protection; the explanation stays until dismissed.
      await this.drop(tabId, true);
      rec.ruleIds = [];
    } else {
      if (rec.m.result === 'found') rec.culprits = await this.describe(rec);
      // 'found' lets only the culprits through, so the page shows what "keep" will give.
      await this.install(rec);
    }
    await this.save(rec);
    return { bisect: viewOf(rec) };
  }

  /** Go on from a 'clean' network bisect: switch cosmetic filters off per list. */
  private async startCosmetic(tabId: number): Promise<Reply> {
    const prev = this.tabs.get(tabId);
    if (!prev || prev.m.result !== 'clean') return { error: 'not clean' };
    if (prev.cos) return { bisect: viewOf(prev) };
    const cands = this.deps.cosmeticCandidates ? await this.deps.cosmeticCandidates(tabId) : null;
    if (!cands) return { error: 'no site' };
    const rec: TabBisect = { ...prev, cos: { stage: 'lists', lists: startBisect(cands.lists) } };
    await this.save(rec);
    if (rec.cos!.lists.result === 'testing') await log.attempt('bisect', () => chrome.tabs.reload(tabId));
    return { bisect: viewOf(rec) };
  }

  private async answerCosmetic(prev: TabBisect, c: CosmeticBisect, works: unknown): Promise<Reply> {
    if (activeMachine(prev).result !== 'testing') return { error: 'not testing' };
    if (typeof works !== 'boolean') return { error: 'invalid answer' };
    let next: CosmeticBisect;
    if (c.stage === 'selectors' && c.selectors) {
      next = { ...c, selectors: answerBisect(c.selectors, works) };
    } else {
      next = { ...c, lists: answerBisect(c.lists, works) };
      if (next.lists.result === 'found') {
        // Narrow the culprit lists down to the selectors they apply on this site.
        const cands = this.deps.cosmeticCandidates ? await this.deps.cosmeticCandidates(prev.tabId) : null;
        const selectors = Array.from(new Set(next.lists.culprits.flatMap((id) => cands?.selectors[id] ?? [])));
        if (selectors.length > 0) next = { ...next, stage: 'selectors', selectors: startBisect(selectors) };
      }
    }
    const rec: TabBisect = { ...prev, cos: next };
    const before = cosmeticOverrideOf(c);
    const after = cosmeticOverrideOf(next);
    await this.save(rec);
    // Reload whenever what is switched off changed (also back to normal for 'clean').
    if (JSON.stringify(before) !== JSON.stringify(after)) await log.attempt('bisect', () => chrome.tabs.reload(prev.tabId));
    return { bisect: viewOf(rec) };
  }

  private async keepCosmetic(rec: TabBisect, c: CosmeticBisect): Promise<Reply> {
    const sel = c.stage === 'selectors' && c.selectors?.result === 'found' ? c.selectors.culprits : [];
    if (sel.length === 0) return { error: 'nothing found' };
    try {
      await this.deps.addCustomFilters(keepCosmeticLines(sel, rec.site, dayKey(Date.now())));
    } catch (e) {
      const msg = errMsg(e);
      return { error: msg === 'locked' ? 'locked' : `save failed: ${msg}` };
    }
    await this.drop(rec.tabId, true);
    return { bisect: null };
  }

  private async keep(tabId: number): Promise<Reply> {
    const rec = this.tabs.get(tabId);
    if (rec?.cos) return this.keepCosmetic(rec, rec.cos);
    if (!rec || rec.m.result !== 'found' || rec.m.culprits.length === 0) return { error: 'nothing found' };
    try {
      const culprits = rec.culprits.length ? rec.culprits : rec.m.culprits.map((host) => ({ host }));
      await this.deps.addCustomFilters(keepFilterLines(culprits, rec.site, dayKey(Date.now())));
    } catch (e) {
      const msg = errMsg(e);
      return { error: msg === 'locked' ? 'locked' : `save failed: ${msg}` };
    }
    await this.drop(tabId, true);
    return { bisect: null };
  }

  /** Hosts blocked on the tab's page load, most blocked first; filter texts only when asked (they cost a map fetch). */
  private async hosts(tabId: number, describe: boolean): Promise<Reply> {
    const { candidates, lists } = collectCandidates(await this.deps.blockedOnTab(tabId));
    const out: NerdBlockedHost[] = [];
    for (const c of candidates) out.push(describe ? await this.describeOne(c, lists[c.host] ?? []) : { ...c, filters: [], lists: lists[c.host] ?? [] });
    return { hosts: out };
  }

  /** "allow <host>": the same narrow exception as "keep", for one host the user names. */
  private async allow(tabId: number, raw: unknown): Promise<Reply> {
    const host = typeof raw === 'string' ? raw.trim().toLowerCase().replace(/\.$/, '') : '';
    if (!isBisectableHost(host)) return { error: 'invalid host' };
    const site = await this.deps.siteOf(tabId);
    if (!site) return { error: 'no site' };
    const { candidates, lists } = collectCandidates(await this.deps.blockedOnTab(tabId));
    const c = candidates.find((x) => x.host === host);
    const d = c ? await this.describeOne(c, lists[host] ?? []) : { host, filters: [] };
    const lines = keepFilterLines([d], site, dayKey(Date.now()), 'allow');
    try {
      await this.deps.addCustomFilters(lines);
    } catch (e) {
      const msg = errMsg(e);
      return { error: msg === 'locked' ? 'locked' : `save failed: ${msg}` };
    }
    return { added: lines.slice(1) };
  }

  /** Badge follows the tab's phase: the step while testing, the normal counter otherwise. */
  private syncBadge(tabId: number): void {
    const rec = this.tabs.get(tabId);
    const text = rec ? badgeStep(activeMachine(rec)) : null;
    if (text !== null) {
      this.badged.add(tabId);
      this.deps.badge?.(tabId, text);
    } else if (this.badged.delete(tabId)) {
      this.deps.badge?.(tabId, null);
    }
  }

  /** The activity badge must not overwrite this tab's step text. */
  holdsBadge(tabId: number): boolean {
    return this.badged.has(tabId);
  }

  /** Nerd mode was switched off: end every bisect and remove its rules. Pages are not reloaded. */
  cancelAll(): Promise<void> {
    if (this.loaded && this.tabs.size === 0) return Promise.resolve();
    return this.serial(async () => {
      await this.ensureLoaded();
      for (const tabId of Array.from(this.tabs.keys())) {
        await this.drop(tabId, false);
        this.syncBadge(tabId);
      }
    });
  }

  async handle(msg: MsgNerdBisect): Promise<Reply> {
    if (msg.action === 'hosts') return this.hosts(msg.tabId, msg.describe === true).catch((e: unknown) => ({ error: errMsg(e) }));
    const reply = await this.serial(async (): Promise<Reply> => {
      try {
        await this.ensureLoaded();
        const tabId = msg.tabId;
        switch (msg.action) {
          case 'state': {
            const rec = this.tabs.get(tabId);
            if (!rec) return { bisect: null };
            // The tab moved to another site while the service worker slept.
            if ((await this.deps.siteOf(tabId)) !== rec.site) {
              await this.drop(tabId, false);
              return { bisect: null };
            }
            return { bisect: viewOf(rec) };
          }
          case 'start':
            return await this.start(tabId);
          case 'answer':
            return await this.answer(tabId, msg.works);
          case 'cosmetic':
            return await this.startCosmetic(tabId);
          case 'keep':
            return await this.keep(tabId);
          case 'allow':
            return await this.allow(tabId, msg.host);
          case 'cancel': {
            const rec = await this.drop(tabId, true);
            return { bisect: rec ? viewOf(rec, 'cancelled') : null };
          }
          default:
            return { error: 'invalid action' };
        }
      } catch (e) {
        log.warn('bisect', msg.action, e);
        return { error: errMsg(e) };
      }
    });
    this.syncBadge(msg.tabId);
    return reply;
  }

  /** The tab closed: drop its rules and state. */
  onTabGone(tabId: number): void {
    void this.serial(async () => {
      await this.ensureLoaded();
      if (this.tabs.has(tabId)) await this.drop(tabId, false);
      this.badged.delete(tabId);
    });
  }

  /**
   * Top-level navigation committed. Test reloads stay on the site; anything
   * else ends the bisect, so the tab-wide allow never follows the user to
   * another site.
   */
  onCommitted(tabId: number, url: string): void {
    if (this.loaded && !this.tabs.has(tabId)) return; // hot path: no bisect on this tab
    void this.serial(async () => {
      await this.ensureLoaded();
      const rec = this.tabs.get(tabId);
      if (rec && siteKey(url) !== rec.site) await this.drop(tabId, false);
      // A navigation resets the tab's badge text: put the step back (or hand the badge back).
      if (this.tabs.has(tabId)) this.badged.delete(tabId);
      this.syncBadge(tabId);
    });
  }

  /**
   * Cosmetic filtering the tab's bisect switches off (CosmeticService asks
   * for every frame). Waits for state restored after a worker restart.
   */
  async cosmeticOverride(tabId: number): Promise<TabCosmeticOverride | null> {
    if (this.loaded && this.tabs.size === 0) return null; // hot path: no bisect anywhere
    await (this.loaded ?? this.serial(() => this.ensureLoaded()));
    return cosmeticOverrideOf(this.tabs.get(tabId)?.cos);
  }

  /** Current view for popup:state (synchronous; the popup asks nerd:bisect 'state' for the authoritative one). */
  view(tabId: number): BisectView | null {
    if (!this.loaded) void this.serial(() => this.ensureLoaded());
    const rec = this.tabs.get(tabId);
    return rec ? viewOf(rec) : null;
  }
}
