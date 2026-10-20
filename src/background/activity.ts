// Bastion Shield service worker — activity log, live stream, attribution and
// history aggregation (ARCHITECTURE §8).
//
// DNR blocks surface as webRequest.onErrorOccurred (net::ERR_BLOCKED_BY_CLIENT)
// and DNR redirects as onBeforeRedirect; both are observed non-blocking. Each
// tab keeps a ring buffer; its counts, third-party hosts and newest events
// (without query strings) are mirrored to storage.session so a restarted
// service worker still knows what happened on the page. List attribution
// comes from declarativeNetRequest.getMatchedRules, rate-limited to stay
// inside Chrome's quota and paused while the popup uses it; attributions that
// arrive after an event was streamed are sent as {type:'attributed'}.
// History (IndexedDB) stores URLs without query or fragment. With the
// activity log off only counts are kept (no hostnames, no events).
//
// Pure helpers are exported for tests; ActivityService receives its I/O.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { LIMITS, LIVE_EVENTS_PER_TAB, RULE_ID, savesRequest } from '../shared/constants.ts';
import { registrableDomain } from '../shared/hash.ts';
import type { ActivityEvent, ActivityKind, DailyAggregate, ListCategory, LivePortMessage, Settings, Totals } from '../shared/types.ts';
import * as log from './log.ts';
import { isSystemAllowRuleId } from './rules.ts';
import { siteKeyFromUrl } from './sites.ts';
import { dayKey, parseUrl, stripQueryAndFragment, truncate, webHostOf } from './util.ts';

export const BLOCKED_ERROR = 'net::ERR_BLOCKED_BY_CLIENT';
export const TOP_N = 500;
export const ATTRIBUTION_WINDOW_MS = 1500;
const MAX_URL_LENGTH = 512;
const MIRROR_DELAY_MS = 1000;
const HISTORY_FLUSH_DELAY_MS = 2000;
const HISTORY_FLUSH_MAX_PENDING = 250;
const TOTALS_SAVE_DELAY_MS = 3000;
const BADGE_DELAY_MS = 250;
const MAX_UNATTRIBUTED = 2000;
const ALL_RECENT_MAX = LIVE_EVENTS_PER_TAB * 2;
const LAST_MATCHED_KEY = 'activity:lastMatchedCall';
/** Events mirrored per tab to storage.session (= tabSummary's default `recent`). */
export const MIRROR_EVENTS = 50;
/** Third-party hosts mirrored per tab. */
export const MIRROR_TP_MAX = 500;
/**
 * getMatchedRules only returns matches of the last five minutes; events
 * older than this are given up on.
 */
export const MATCHED_RULES_HORIZON_MS = 4 * 60_000;
/** The popup calls getMatchedRules itself; our own polling pauses this long after it opens. */
export const POPUP_ATTRIBUTION_BACKOFF_MS = 60_000;
export const CUSTOM_LIST_USER = 'custom';
export const CUSTOM_LIST_ADMIN = 'admin';
/** Pseudo list id for matches of imported lists ("My lists"). */
export const CUSTOM_LIST_MY = 'my-lists';

/** Minimal webRequest details we read (onErrorOccurred / onBeforeRedirect). */
export interface RequestDetails {
  tabId: number;
  frameId: number;
  url: string;
  type: string;
  timeStamp: number;
  initiator?: string;
  error?: string;
  redirectUrl?: string;
  statusCode?: number;
}

export interface RedirectClass {
  kind: ActivityKind;
  listId?: string;
}

const EXT_SCHEME = /^(?:chrome-extension|extension):$/;

/**
 * Classify an onBeforeRedirect: redirects into an extension package are
 * ours (strict-block page, bounce page, neutered resources), and an internal
 * redirect that only removed query parameters is parameter stripping.
 */
export function classifyRedirect(url: string, redirectUrl: string, statusCode?: number): RedirectClass | null {
  const to = parseUrl(redirectUrl);
  if (!to) return null;
  if (EXT_SCHEME.test(to.protocol)) {
    if (to.pathname === '/pages/blocked.html') {
      const listId = to.searchParams.get('list') ?? undefined;
      return listId ? { kind: 'strict', listId } : { kind: 'strict' };
    }
    if (to.pathname === '/pages/bounce.html') return { kind: 'debounced' };
    return { kind: 'redirected' };
  }
  const from = parseUrl(url);
  if (!from) return null;
  // DNR redirects are internal 307s; a server can also redirect, so be strict.
  if (statusCode !== undefined && statusCode !== 307) return null;
  if (from.origin !== to.origin || from.pathname !== to.pathname || from.search === to.search) return null;
  const before = new URLSearchParams(from.search);
  const after = new URLSearchParams(to.search);
  const beforeKeys = new Set(before.keys());
  let removed = 0;
  for (const k of beforeKeys) if (!after.has(k)) removed++;
  for (const k of after.keys()) if (!beforeKeys.has(k)) return null;
  return removed > 0 ? { kind: 'stripped' } : null;
}

/** Build an event; `pageSite` is the tab's top-level site key when known. */
export function makeEvent(d: RequestDetails, kind: ActivityKind, pageSite: string | null, listId?: string): ActivityEvent | null {
  const host = webHostOf(d.url);
  if (!host) return null;
  let site = pageSite ?? siteKeyFromUrl(d.initiator) ?? '';
  if (d.type === 'main_frame') site = siteKeyFromUrl(d.url) ?? site;
  const thirdParty = site !== '' && registrableDomain(host) !== registrableDomain(site);
  const ev: ActivityEvent = {
    t: Math.round(d.timeStamp || Date.now()),
    tabId: d.tabId,
    frameId: d.frameId,
    kind,
    url: truncate(d.url, MAX_URL_LENGTH),
    host,
    type: d.type,
    site,
    thirdParty,
  };
  if (listId) ev.list = listId;
  return ev;
}

/** Copy for persistence: never store query strings or fragments. */
export function historyRecord(ev: ActivityEvent): ActivityEvent {
  const r: ActivityEvent = { ...ev, url: stripQueryAndFragment(ev.url) };
  return r;
}

// ---------------------------------------------------------------------------
// Aggregates and totals
// ---------------------------------------------------------------------------

export function emptyDaily(day: string): DailyAggregate {
  return { day, total: 0, byKind: {}, byCategory: {}, byHost: {}, bySite: {}, byType: {}, savedByType: {} };
}

function bump<K extends string>(rec: Partial<Record<K, number>>, key: K, n = 1): void {
  const v = (rec[key] ?? 0) + n;
  if (v <= 0) delete rec[key];
  else rec[key] = v;
}

/** Keep the `n` largest entries (ties broken by key for determinism). */
export function trimTop(rec: Record<string, number>, n = TOP_N): Record<string, number> {
  const keys = Object.keys(rec);
  if (keys.length <= n) return rec;
  const kept = keys.sort((a, b) => rec[b] - rec[a] || (a < b ? -1 : 1)).slice(0, n);
  const out: Record<string, number> = {};
  for (const k of kept) out[k] = rec[k];
  return out;
}

export function addEventToDaily(agg: DailyAggregate, ev: ActivityEvent, category: ListCategory | 'unknown'): void {
  agg.total += 1;
  bump(agg.byKind, ev.kind);
  bump(agg.byCategory, category);
  bump(agg.byHost, ev.host);
  if (ev.site) bump(agg.bySite, ev.site);
  bump(agg.byType, ev.type || 'other');
  if (savesRequest(ev.kind)) bump((agg.savedByType ??= {}), ev.type || 'other');
}

/** Sum two aggregates of the same day (deltas may be negative); top-N trimmed. */
export function mergeDaily(a: DailyAggregate, b: DailyAggregate): DailyAggregate {
  const out: DailyAggregate = {
    day: a.day,
    total: Math.max(0, a.total + b.total),
    byKind: { ...a.byKind },
    byCategory: { ...a.byCategory },
    byHost: { ...a.byHost },
    bySite: { ...a.bySite },
    byType: { ...a.byType },
  };
  // A day recorded before savedByType existed keeps going without it (the
  // overview then estimates from byType): a partial count would understate it.
  const legacy = a.savedByType === undefined && a.total > 0;
  if (!legacy) {
    out.savedByType = { ...a.savedByType };
    for (const [k, v] of Object.entries(b.savedByType ?? {})) bump(out.savedByType, k, v);
  }
  for (const [k, v] of Object.entries(b.byKind)) bump(out.byKind, k as ActivityKind, v ?? 0);
  for (const [k, v] of Object.entries(b.byCategory)) bump(out.byCategory, k as ListCategory | 'unknown', v ?? 0);
  for (const [k, v] of Object.entries(b.byHost)) bump(out.byHost, k, v);
  for (const [k, v] of Object.entries(b.bySite)) bump(out.bySite, k, v);
  for (const [k, v] of Object.entries(b.byType)) bump(out.byType, k, v);
  out.byHost = trimTop(out.byHost);
  out.bySite = trimTop(out.bySite);
  return out;
}

/** Group events into per-day aggregates. */
export function aggregateEvents(events: readonly ActivityEvent[], categoryOf: (ev: ActivityEvent) => ListCategory | 'unknown'): DailyAggregate[] {
  const days = new Map<string, DailyAggregate>();
  for (const ev of events) {
    const day = dayKey(ev.t);
    let agg = days.get(day);
    if (!agg) {
      agg = emptyDaily(day);
      days.set(day, agg);
    }
    addEventToDaily(agg, ev, categoryOf(ev));
  }
  return Array.from(days.values());
}

/** "Requests prevented" = blocked + strict + redirected (neutered); every kind is in byKind. */
export function countsAsBlocked(kind: ActivityKind): boolean {
  return kind === 'blocked' || kind === 'strict' || kind === 'redirected';
}

export function emptyTotals(now: number): Totals {
  return { since: now, blocked: 0, byKind: {} };
}

export function bumpTotals(t: Totals, ev: ActivityEvent): void {
  if (countsAsBlocked(ev.kind)) t.blocked += 1;
  bump(t.byKind, ev.kind);
}

export function sanitizeTotals(raw: unknown, now: number): Totals {
  if (!raw || typeof raw !== 'object') return emptyTotals(now);
  const r = raw as Partial<Totals>;
  const out = emptyTotals(typeof r.since === 'number' && Number.isFinite(r.since) ? r.since : now);
  if (typeof r.blocked === 'number' && Number.isFinite(r.blocked) && r.blocked >= 0) out.blocked = Math.floor(r.blocked);
  if (r.byKind && typeof r.byKind === 'object') {
    for (const k of ['blocked', 'redirected', 'stripped', 'debounced', 'strict'] as const) {
      const v = r.byKind[k];
      if (typeof v === 'number' && Number.isFinite(v) && v > 0) out.byKind[k] = Math.floor(v);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Attribution
// ---------------------------------------------------------------------------

export interface MatchInfo {
  rule: { ruleId: number; rulesetId: string };
  tabId: number;
  timeStamp: number;
}

/** List id for a matched rule; dynamic custom/admin ranges map to pseudo lists. */
export function listForRule(rulesetId: string, ruleId: number, rulesetToList: Record<string, string>): string | undefined {
  if (rulesetId === '_dynamic') {
    if (ruleId >= RULE_ID.CUSTOM_START && ruleId <= RULE_ID.CUSTOM_END) return CUSTOM_LIST_USER;
    if (ruleId >= RULE_ID.ADMIN_START && ruleId <= RULE_ID.ADMIN_END) return CUSTOM_LIST_ADMIN;
    if (ruleId >= RULE_ID.MY_LISTS_START && ruleId <= RULE_ID.MY_LISTS_END) return CUSTOM_LIST_MY;
    return undefined;
  }
  if (rulesetId === '_session') return undefined;
  return rulesetToList[rulesetId];
}

/** Closest unused match to `t` within ±windowMs in a timestamp-sorted bucket. */
function nearestMatch(arr: readonly MatchInfo[] | undefined, t: number, windowMs: number, used: ReadonlySet<MatchInfo>): MatchInfo | null {
  if (!arr || arr.length === 0) return null;
  // Binary search for the first match at or after t - window.
  let lo = 0;
  let hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (arr[mid].timeStamp < t - windowMs) lo = mid + 1;
    else hi = mid;
  }
  let best: MatchInfo | null = null;
  let bestDelta = Infinity;
  for (let i = lo; i < arr.length && arr[i].timeStamp <= t + windowMs; i++) {
    const m = arr[i];
    if (used.has(m)) continue;
    const delta = Math.abs(m.timeStamp - t);
    if (delta < bestDelta) {
      best = m;
      bestDelta = delta;
    }
  }
  return best;
}

/**
 * Join unattributed events with getMatchedRules results on (tabId, closest
 * timestamp within the window). Each match is used once. Chromium moves the
 * matches of a document the tab navigated away from to tabId -1, so events
 * without a match in their own tab are joined with that bucket too. Mutates
 * the events it attributes and returns them.
 */
export function attributeEvents(
  events: readonly ActivityEvent[],
  matches: readonly MatchInfo[],
  rulesetToList: Record<string, string>,
  windowMs = ATTRIBUTION_WINDOW_MS,
): ActivityEvent[] {
  const byTab = new Map<number, MatchInfo[]>();
  for (const m of matches) {
    if (!m || !m.rule || typeof m.timeStamp !== 'number') continue;
    if (isSystemAllowRuleId(m.rule.rulesetId, m.rule.ruleId)) continue;
    let arr = byTab.get(m.tabId);
    if (!arr) byTab.set(m.tabId, (arr = []));
    arr.push(m);
  }
  for (const arr of byTab.values()) arr.sort((a, b) => a.timeStamp - b.timeStamp);
  const used = new Set<MatchInfo>();
  const out: ActivityEvent[] = [];
  const sorted = [...events].sort((a, b) => a.t - b.t);
  for (const ev of sorted) {
    if (ev.rule) continue;
    let best = nearestMatch(byTab.get(ev.tabId), ev.t, windowMs, used);
    if (!best && ev.tabId !== -1) best = nearestMatch(byTab.get(-1), ev.t, windowMs, used);
    if (!best) continue;
    used.add(best);
    ev.rule = `${best.rule.rulesetId}:${best.rule.ruleId}`;
    const list = ev.list ?? listForRule(best.rule.rulesetId, best.rule.ruleId, rulesetToList);
    if (list) ev.list = list;
    out.push(ev);
  }
  return out;
}

/** Compact badge text (the badge has room for about four characters). */
export function badgeText(n: number): string {
  if (n <= 0) return '';
  if (n < 1000) return String(n);
  if (n < 10_000) return `${Math.floor(n / 1000)}k`;
  return '9k+';
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export interface TabCounts {
  /** DNR blocks and strict blocks. */
  blocked: number;
  /** Surrogate stubs served (DNR redirect to a neutered resource). */
  redirected: number;
  stripped: number;
  /** Bounce trackers skipped. */
  debounced: number;
}

interface TabState {
  site: string;
  url: string;
  events: ActivityEvent[];
  counts: TabCounts;
  thirdParty: Set<string>;
}

interface TabMirror {
  site: string;
  url: string;
  counts: TabCounts;
  tp: string[];
  events: ActivityEvent[];
}

export interface HistoryStore {
  /** Persist records and merge the per-day deltas; returns the record keys in order. */
  write(records: ActivityEvent[], dailyDeltas: DailyAggregate[]): Promise<number[]>;
  /** Replace stored records (after late attribution) and merge deltas. */
  patch(updates: { key: number; record: ActivityEvent }[], dailyDeltas: DailyAggregate[]): Promise<void>;
}

export interface LivePort {
  postMessage(msg: LivePortMessage): void;
}

export type BadgeMode = 'browser' | 'self' | 'off';

export interface ActivityConfig {
  activityLog: boolean;
  historyEnabled: boolean;
  /** false with retentionDays 0: only the daily aggregate is kept, no individual events. */
  keepEvents?: boolean;
  badgeMode: BadgeMode;
  rulesetToList: Record<string, string>;
  categoryOf(listId: string | undefined): ListCategory | 'unknown';
  /** false in an incognito context: totals are kept in memory only, never written. */
  persistTotals?: boolean;
}

/**
 * Persistence switches for one extension instance. An incognito (split mode)
 * instance never writes history or totals: its activity stays in memory.
 */
export function persistenceFor(settings: Settings, incognito: boolean): Required<Pick<ActivityConfig, 'historyEnabled' | 'keepEvents' | 'persistTotals'>> {
  return {
    historyEnabled: !incognito && settings.ui.activityLog && settings.history.enabled,
    keepEvents: settings.history.retentionDays > 0,
    persistTotals: !incognito,
  };
}

export interface ActivityDeps {
  now(): number;
  config(): ActivityConfig;
  sessionGet(key: string): Promise<unknown>;
  sessionSet(items: Record<string, unknown>): Promise<void>;
  sessionRemove(keys: string[]): Promise<void>;
  getMatchedRules(minTimeStamp: number): Promise<MatchInfo[]>;
  history: HistoryStore;
  loadTotals(): Promise<unknown>;
  saveTotals(t: Totals): Promise<void>;
  /** null resets the tab-specific text. */
  setBadge(tabId: number, text: string | null): Promise<void>;
  setTimeout(fn: () => void, ms: number): unknown;
}

export class ActivityService {
  private readonly deps: ActivityDeps;
  private readonly tabs = new Map<number, TabState>();
  private readonly restoring = new Map<number, Promise<TabState>>();
  private readonly allRecent: ActivityEvent[] = [];
  private readonly ports = new Map<LivePort, number | 'all' | null>();
  private readonly dirtyTabs = new Set<number>();
  private readonly badgeDirty = new Set<number>();
  private readonly historyKeys = new WeakMap<ActivityEvent, number>();
  /** Events already counted in the daily aggregates -> category they were counted under. */
  private readonly flushed = new WeakMap<ActivityEvent, ListCategory | 'unknown'>();
  private unattributed: ActivityEvent[] = [];
  private pendingHistory: ActivityEvent[] = [];
  private queue: Promise<void> = Promise.resolve();
  private totals: Totals;
  private totalsLoaded = false;
  private mirrorTimer: unknown = null;
  private historyTimer: unknown = null;
  private totalsTimer: unknown = null;
  private badgeTimer: unknown = null;
  private attributionTimer: unknown = null;
  private lastMatchedCall = 0;
  /** No own getMatchedRules call before this time (the popup is using the quota). */
  private attributionPausedUntil = 0;
  private attributing = false;
  private badgeMode: BadgeMode | null = null;

  constructor(deps: ActivityDeps) {
    this.deps = deps;
    this.totals = emptyTotals(deps.now());
  }

  async init(): Promise<void> {
    const [raw, last] = await Promise.all([this.deps.loadTotals().catch(() => null), this.deps.sessionGet(LAST_MATCHED_KEY).catch(() => null)]);
    this.totals = sanitizeTotals(raw, this.deps.now());
    this.totalsLoaded = true;
    // The getMatchedRules quota is per extension, not per worker instance.
    if (typeof last === 'number' && Number.isFinite(last) && last <= this.deps.now()) this.lastMatchedCall = last;
  }

  getTotals(): Totals {
    return { ...this.totals, byKind: { ...this.totals.byKind } };
  }

  resetTotals(): void {
    this.totals = emptyTotals(this.deps.now());
    this.scheduleTotals();
  }

  /** Serialize event processing so tab restores never reorder events. */
  private enqueue(fn: () => Promise<void> | void): Promise<void> {
    this.queue = this.queue.then(fn).catch((e: unknown) => log.warn('activity', e));
    return this.queue;
  }

  private newTab(site: string, url: string): TabState {
    return { site, url, events: [], counts: { blocked: 0, redirected: 0, stripped: 0, debounced: 0 }, thirdParty: new Set() };
  }

  private tabState(tabId: number): Promise<TabState> {
    const t = this.tabs.get(tabId);
    if (t) return Promise.resolve(t);
    let p = this.restoring.get(tabId);
    if (!p) {
      p = this.deps
        .sessionGet(`tab:${tabId}`)
        .catch(() => null)
        .then((raw) => {
          const existing = this.tabs.get(tabId);
          if (existing) return existing;
          const state = this.fromMirror(raw);
          this.tabs.set(tabId, state);
          this.restoring.delete(tabId);
          return state;
        });
      this.restoring.set(tabId, p);
    }
    return p;
  }

  private fromMirror(raw: unknown): TabState {
    const m = raw as Partial<TabMirror> | null;
    if (!m || typeof m !== 'object') return this.newTab('', '');
    const s = this.newTab(typeof m.site === 'string' ? m.site : '', typeof m.url === 'string' ? m.url : '');
    if (Array.isArray(m.events)) s.events = m.events.filter((e) => e && typeof e === 'object' && typeof e.t === 'number').slice(-LIVE_EVENTS_PER_TAB);
    if (m.counts && typeof m.counts === 'object') {
      s.counts.blocked = Number(m.counts.blocked) || 0;
      s.counts.redirected = Number(m.counts.redirected) || 0;
      s.counts.stripped = Number(m.counts.stripped) || 0;
      s.counts.debounced = Number((m.counts as Partial<TabCounts>).debounced) || 0;
    }
    if (Array.isArray(m.tp)) for (const h of m.tp) if (typeof h === 'string') s.thirdParty.add(h);
    return s;
  }

  /** webRequest.onErrorOccurred */
  onError(d: RequestDetails): void {
    if (d.error !== BLOCKED_ERROR) return;
    void this.enqueue(() => this.record(d, 'blocked'));
  }

  /** webRequest.onBeforeRedirect; `onStrict` lets blocked.ts remember the original URL. */
  onRedirect(d: RequestDetails, onStrict?: (tabId: number, url: string, listId: string | undefined) => void): RedirectClass | null {
    if (!d.redirectUrl) return null;
    const cls = classifyRedirect(d.url, d.redirectUrl, d.statusCode);
    if (!cls) return null;
    if (cls.kind === 'strict' && onStrict && d.tabId >= 0) onStrict(d.tabId, d.url, cls.listId);
    void this.enqueue(() => this.record(d, cls.kind, cls.listId));
    return cls;
  }

  /** webNavigation.onCommitted for top frames: a new page load starts with zero counts. */
  onCommitted(tabId: number, url: string): void {
    void this.enqueue(() => {
      const state = this.newTab(siteKeyFromUrl(url) ?? '', truncate(url, MAX_URL_LENGTH));
      this.tabs.set(tabId, state);
      this.restoring.delete(tabId);
      this.dirtyTabs.add(tabId);
      this.scheduleMirror();
      this.broadcast(tabId, { type: 'reset', tabId });
      if (this.deps.config().badgeMode === 'self') {
        this.badgeDirty.add(tabId);
        this.scheduleBadge();
      }
    });
  }

  onTabRemoved(tabId: number): void {
    void this.enqueue(async () => {
      this.tabs.delete(tabId);
      this.dirtyTabs.delete(tabId);
      this.badgeDirty.delete(tabId);
      await this.deps.sessionRemove([`tab:${tabId}`]).catch(() => undefined);
    });
  }

  onTabReplaced(addedTabId: number, removedTabId: number): void {
    void this.enqueue(async () => {
      const s = this.tabs.get(removedTabId);
      if (s) {
        this.tabs.set(addedTabId, s);
        this.tabs.delete(removedTabId);
        this.dirtyTabs.add(addedTabId);
        this.scheduleMirror();
      }
      await this.deps.sessionRemove([`tab:${removedTabId}`]).catch(() => undefined);
    });
  }

  private async record(d: RequestDetails, kind: ActivityKind, listId?: string): Promise<void> {
    const cfg = this.deps.config();
    if (!cfg.activityLog && cfg.badgeMode !== 'self') return;
    const tab = d.tabId >= 0 ? await this.tabState(d.tabId) : null;
    const ev = makeEvent(d, kind, tab && tab.site ? tab.site : null, listId);
    if (!ev) return;
    if (tab) {
      if (kind === 'blocked' || kind === 'strict') tab.counts.blocked++;
      else if (kind === 'redirected') tab.counts.redirected++;
      else if (kind === 'debounced') tab.counts.debounced++;
      else if (kind === 'stripped') tab.counts.stripped++;
      // Counts survive a worker restart in both paths (popup counters, badge).
      this.dirtyTabs.add(d.tabId);
      this.scheduleMirror();
      if (cfg.badgeMode === 'self') {
        this.badgeDirty.add(d.tabId);
        this.scheduleBadge();
      }
    }
    bumpTotals(this.totals, ev);
    this.scheduleTotals();
    // Below this line only with the activity log on: the badge-only path
    // keeps counts, no hostnames (data minimisation, PRIVACY.md).
    if (!cfg.activityLog) return;
    if (tab) {
      if (ev.thirdParty) tab.thirdParty.add(ev.host);
      tab.events.push(ev);
      if (tab.events.length > LIVE_EVENTS_PER_TAB) tab.events.splice(0, tab.events.length - LIVE_EVENTS_PER_TAB);
    }
    this.allRecent.push(ev);
    if (this.allRecent.length > ALL_RECENT_MAX) this.allRecent.splice(0, this.allRecent.length - ALL_RECENT_MAX);
    this.broadcast(ev.tabId, { type: 'event', event: ev });
    if (!ev.list || !ev.rule) {
      this.unattributed.push(ev);
      if (this.unattributed.length > MAX_UNATTRIBUTED) this.unattributed.splice(0, this.unattributed.length - MAX_UNATTRIBUTED);
      this.scheduleAttribution();
    }
    if (cfg.historyEnabled) {
      this.pendingHistory.push(ev);
      this.scheduleHistory(this.pendingHistory.length >= HISTORY_FLUSH_MAX_PENDING ? 0 : HISTORY_FLUSH_DELAY_MS);
    }
  }

  // --- live ports -----------------------------------------------------------

  addPort(port: LivePort): void {
    this.ports.set(port, null);
  }

  removePort(port: LivePort): void {
    this.ports.delete(port);
  }

  async subscribe(port: LivePort, target: number | 'all'): Promise<void> {
    if (!this.ports.has(port)) return;
    await this.queue;
    if (target !== 'all') await this.tabState(target);
    if (!this.ports.has(port)) return;
    // From here on synchronous: no event can slip between backlog and live stream.
    this.ports.set(port, target);
    const events = target === 'all' ? this.allRecent.slice() : (this.tabs.get(target)?.events.slice() ?? []);
    try {
      port.postMessage({ type: 'backlog', events });
    } catch {
      this.ports.delete(port);
    }
    this.scheduleAttribution();
  }

  private broadcast(tabId: number, msg: LivePortMessage): void {
    for (const [port, target] of this.ports) {
      if (target === null) continue;
      if (target !== 'all' && target !== tabId) continue;
      try {
        port.postMessage(msg);
      } catch {
        this.ports.delete(port);
      }
    }
  }

  hasListeners(): boolean {
    for (const t of this.ports.values()) if (t !== null) return true;
    return false;
  }

  // --- queries for the popup ------------------------------------------------

  async tabSummary(tabId: number, recent = 50): Promise<{ counts: TabCounts & { thirdPartyHosts: number }; recent: ActivityEvent[] }> {
    await this.queue;
    const s = await this.tabState(tabId);
    return {
      counts: { ...s.counts, thirdPartyHosts: s.thirdParty.size },
      recent: s.events.slice(-recent),
    };
  }

  // --- timers -----------------------------------------------------------------

  private scheduleMirror(): void {
    if (this.mirrorTimer !== null) return;
    this.mirrorTimer = this.deps.setTimeout(() => {
      this.mirrorTimer = null;
      void this.flushMirror();
    }, MIRROR_DELAY_MS);
  }

  /**
   * Mirror what a restarted worker needs: counts, a bounded third-party host
   * set and the newest MIRROR_EVENTS events without query strings (about
   * 10-15 KiB per busy tab, so hundreds of tabs fit into storage.session).
   */
  async flushMirror(): Promise<void> {
    if (this.dirtyTabs.size === 0) return;
    const items: Record<string, unknown> = {};
    for (const id of this.dirtyTabs) {
      const s = this.tabs.get(id);
      if (!s) continue;
      const m: TabMirror = {
        site: s.site,
        url: s.url,
        counts: { ...s.counts },
        tp: Array.from(s.thirdParty).slice(0, MIRROR_TP_MAX),
        events: s.events.slice(-MIRROR_EVENTS).map((e) => ({ ...e, url: stripQueryAndFragment(e.url) })),
      };
      items[`tab:${id}`] = m;
    }
    this.dirtyTabs.clear();
    try {
      await this.deps.sessionSet(items);
    } catch (e) {
      // storage.session is full (10 MiB): keep the counts and hosts, drop the events.
      log.warn('activity', 'mirror', e);
      for (const v of Object.values(items)) (v as TabMirror).events = [];
      await this.deps.sessionSet(items).catch(() => undefined);
    }
  }

  private persistTotals(): boolean {
    return this.totalsLoaded && this.deps.config().persistTotals !== false;
  }

  private scheduleTotals(): void {
    if (this.totalsTimer !== null) return;
    this.totalsTimer = this.deps.setTimeout(() => {
      this.totalsTimer = null;
      if (this.persistTotals()) void this.deps.saveTotals(this.getTotals()).catch((e: unknown) => log.warn('activity', 'totals', e));
    }, TOTALS_SAVE_DELAY_MS);
  }

  private scheduleBadge(): void {
    if (this.badgeTimer !== null) return;
    this.badgeTimer = this.deps.setTimeout(() => {
      this.badgeTimer = null;
      const ids = Array.from(this.badgeDirty);
      this.badgeDirty.clear();
      for (const id of ids) {
        const s = this.tabs.get(id);
        const n = s ? s.counts.blocked + s.counts.redirected + s.counts.stripped + s.counts.debounced : 0;
        void this.deps.setBadge(id, badgeText(n)).catch(() => undefined);
      }
    }, BADGE_DELAY_MS);
  }

  /** Re-render every known tab's badge (after switching badge modes). */
  refreshBadges(): void {
    for (const id of this.tabs.keys()) this.badgeDirty.add(id);
    this.scheduleBadge();
  }

  /**
   * Called by applyAll. Leaving "self" mode resets our per-tab texts (null
   * falls back to the browser's own counter or no badge); entering it
   * renders the counts we already have.
   */
  setBadgeMode(mode: BadgeMode): void {
    const prev = this.badgeMode;
    this.badgeMode = mode;
    if (prev === mode) return;
    if (mode === 'self') {
      this.refreshBadges();
    } else if (prev === 'self') {
      for (const id of this.tabs.keys()) void this.deps.setBadge(id, null).catch(() => undefined);
    }
  }

  private scheduleHistory(delay: number): void {
    if (this.historyTimer !== null && delay > 0) return;
    this.historyTimer = this.deps.setTimeout(() => {
      this.historyTimer = null;
      void this.flushHistory();
    }, delay);
  }

  async flushHistory(): Promise<void> {
    const batch = this.pendingHistory;
    if (batch.length === 0) return;
    this.pendingHistory = [];
    if (!this.deps.config().historyEnabled) return;
    const cfg = this.deps.config();
    const keep = cfg.keepEvents !== false;
    const records = keep ? batch.map(historyRecord) : [];
    // Categories as written, so a later attribution can move the counts.
    const written = new Map(batch.map((ev) => [ev, { list: ev.list, rule: ev.rule }] as const));
    const deltas = aggregateEvents(batch, (ev) => cfg.categoryOf(ev.list));
    try {
      const keys = await this.deps.history.write(records, deltas);
      batch.forEach((ev, i) => {
        this.flushed.set(ev, cfg.categoryOf(written.get(ev)?.list));
        if (keep && typeof keys[i] === 'number') this.historyKeys.set(ev, keys[i]);
      });
      // Attribution may have landed while the write was in flight.
      const late = batch.filter((ev) => {
        const w = written.get(ev);
        return w !== undefined && (w.list !== ev.list || w.rule !== ev.rule);
      });
      if (late.length > 0) await this.patchHistory(late);
    } catch (e) {
      log.warn('activity', 'history write', e);
    }
  }

  // --- attribution ------------------------------------------------------------

  /** Earliest time our next own getMatchedRules call may happen. */
  private nextAttributionAt(): number {
    return Math.max(this.lastMatchedCall + LIMITS.GET_MATCHED_RULES_MIN_INTERVAL_MS, this.attributionPausedUntil);
  }

  /**
   * The popup asked for its state: it calls getMatchedRules itself, so our
   * own polling backs off to leave it the shared quota.
   */
  notePopupQuery(): void {
    this.attributionPausedUntil = this.deps.now() + POPUP_ATTRIBUTION_BACKOFF_MS;
  }

  private scheduleAttribution(): void {
    if (this.unattributed.length === 0 || this.attributionTimer !== null) return;
    const cfg = this.deps.config();
    if (!this.hasListeners() && !cfg.historyEnabled) return;
    const wait = Math.max(0, this.nextAttributionAt() - this.deps.now());
    this.attributionTimer = this.deps.setTimeout(() => {
      this.attributionTimer = null;
      void this.attribute();
    }, Math.max(wait, 500));
  }

  async attribute(): Promise<void> {
    if (this.attributing || this.unattributed.length === 0) return;
    const now = this.deps.now();
    if (now < this.nextAttributionAt()) {
      this.scheduleAttribution();
      return;
    }
    this.attributing = true;
    this.lastMatchedCall = now;
    void this.deps.sessionSet({ [LAST_MATCHED_KEY]: now }).catch(() => undefined);
    try {
      const events = this.unattributed;
      const minTimeStamp = Math.min(...events.map((e) => e.t)) - ATTRIBUTION_WINDOW_MS;
      const matches = await this.deps.getMatchedRules(minTimeStamp);
      const cfg = this.deps.config();
      const done = attributeEvents(events, matches, cfg.rulesetToList);
      const doneSet = new Set(done);
      // Events older than the matched-rules horizon will never be attributed.
      this.unattributed = events.filter((e) => !doneSet.has(e) && now - e.t < MATCHED_RULES_HORIZON_MS);
      this.broadcastAttributed(done);
      await this.patchHistory(done);
    } catch (e) {
      // Quota exhausted (the popup may have used it) or API unavailable: retry later.
      log.warn('activity', 'getMatchedRules', e);
    } finally {
      this.attributing = false;
    }
    if (this.unattributed.length > 0) this.scheduleAttribution();
  }

  /**
   * Tell live listeners about list attributions of events they already
   * received (only logged events are ever attributed, and those were streamed).
   */
  private broadcastAttributed(done: readonly ActivityEvent[]): void {
    if (done.length === 0 || !this.hasListeners()) return;
    const byTab = new Map<number, Extract<LivePortMessage, { type: 'attributed' }>['updates']>();
    for (const ev of done) {
      if (!ev.list) continue;
      let arr = byTab.get(ev.tabId);
      if (!arr) byTab.set(ev.tabId, (arr = []));
      const u: (typeof arr)[number] = { t: ev.t, tabId: ev.tabId, url: ev.url, kind: ev.kind, list: ev.list };
      if (ev.rule) u.rule = ev.rule;
      arr.push(u);
    }
    for (const [tabId, updates] of byTab) this.broadcast(tabId, { type: 'attributed', updates });
  }

  /** Correct persisted records and category counts of events attributed after they were written. */
  private async patchHistory(done: ActivityEvent[]): Promise<void> {
    const cfg = this.deps.config();
    if (!cfg.historyEnabled) return;
    const updates: { key: number; record: ActivityEvent }[] = [];
    const deltas = new Map<string, DailyAggregate>();
    for (const ev of done) {
      const oldCat = this.flushed.get(ev);
      if (oldCat === undefined) continue; // not written yet: it will be written attributed
      const key = this.historyKeys.get(ev);
      if (key !== undefined) updates.push({ key, record: historyRecord(ev) });
      const newCat = cfg.categoryOf(ev.list);
      this.flushed.set(ev, newCat);
      if (oldCat === newCat) continue;
      const day = dayKey(ev.t);
      let d = deltas.get(day);
      if (!d) deltas.set(day, (d = emptyDaily(day)));
      d.byCategory[oldCat] = (d.byCategory[oldCat] ?? 0) - 1;
      d.byCategory[newCat] = (d.byCategory[newCat] ?? 0) + 1;
    }
    if (updates.length === 0 && deltas.size === 0) return;
    await this.deps.history.patch(updates, Array.from(deltas.values())).catch((e: unknown) => log.warn('activity', 'history patch', e));
  }

  /** Flush everything that is buffered (before history queries, on suspend). */
  async flushAll(): Promise<void> {
    await this.queue;
    await Promise.all([this.flushHistory(), this.flushMirror(), this.persistTotals() ? this.deps.saveTotals(this.getTotals()).catch(() => undefined) : undefined]);
  }

  /** Drop everything persisted per tab (history:clear keeps the live view consistent). */
  clearLive(): void {
    for (const s of this.tabs.values()) {
      s.events = [];
    }
    this.allRecent.length = 0;
    this.unattributed = [];
    this.pendingHistory = [];
  }
}
