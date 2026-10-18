// Tests for the activity log: request classification, aggregation, top-N
// trimming, totals, getMatchedRules attribution and the ActivityService flow
// with injected storage/history/badge (src/background/activity.ts).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LIVE_EVENTS_PER_TAB, RULE_ID } from '../../src/shared/constants.ts';
import type { ActivityEvent, DailyAggregate, LivePortMessage, Totals } from '../../src/shared/types.ts';
import {
  ActivityService,
  addEventToDaily,
  aggregateEvents,
  attributeEvents,
  badgeText,
  bumpTotals,
  classifyRedirect,
  emptyDaily,
  emptyTotals,
  historyRecord,
  listForRule,
  makeEvent,
  MATCHED_RULES_HORIZON_MS,
  mergeDaily,
  MIRROR_EVENTS,
  persistenceFor,
  MIRROR_TP_MAX,
  POPUP_ATTRIBUTION_BACKOFF_MS,
  sanitizeTotals,
  trimTop,
} from '../../src/background/activity.ts';
import type { ActivityConfig, ActivityDeps, BadgeMode, MatchInfo, RequestDetails } from '../../src/background/activity.ts';
import { dayKey } from '../../src/background/util.ts';
import { defaultSettings, normalizeSettings } from '../../src/background/settings.ts';

const EXT = 'chrome-extension://0123456789abcdef0123456789abcdef';

test('classifyRedirect recognises our pages, neutered resources and stripping', () => {
  assert.deepEqual(classifyRedirect('https://evil.ch/', `${EXT}/pages/blocked.html?list=ublock-badware`), { kind: 'strict', listId: 'ublock-badware' });
  assert.deepEqual(classifyRedirect('https://t.co/x', `${EXT}/pages/bounce.html#https%3A%2F%2Fa.ch`), { kind: 'debounced' });
  assert.deepEqual(classifyRedirect('https://ads.net/gpt.js', `${EXT}/war/googletagservices_gpt.js`), { kind: 'redirected' });
  assert.deepEqual(classifyRedirect('https://shop.ch/p?id=1&fbclid=abc&gclid=x', 'https://shop.ch/p?id=1', 307), { kind: 'stripped' });
  // Server redirects, HTTPS upgrades and added parameters are not ours.
  assert.equal(classifyRedirect('https://shop.ch/p?a=1&b=2', 'https://shop.ch/p?a=1', 301), null);
  assert.equal(classifyRedirect('http://shop.ch/p?a=1', 'https://shop.ch/p?a=1', 307), null);
  assert.equal(classifyRedirect('https://shop.ch/p?a=1', 'https://shop.ch/p?a=1&c=3', 307), null);
  assert.equal(classifyRedirect('https://shop.ch/p', 'https://other.ch/p', 307), null);
  assert.equal(classifyRedirect('https://shop.ch/p', 'garbage'), null);
});

function details(over: Partial<RequestDetails> = {}): RequestDetails {
  return { tabId: 4, frameId: 0, url: 'https://ads.doubleclick.net/x.js?a=1#f', type: 'script', timeStamp: 1_700_000_000_000, initiator: 'https://www.nzz.ch', ...over };
}

test('makeEvent derives site and third-party status', () => {
  const ev = makeEvent(details(), 'blocked', 'nzz.ch')!;
  assert.equal(ev.host, 'ads.doubleclick.net');
  assert.equal(ev.site, 'nzz.ch');
  assert.equal(ev.thirdParty, true);
  const firstParty = makeEvent(details({ url: 'https://static.nzz.ch/t.js' }), 'blocked', null)!;
  assert.equal(firstParty.site, 'nzz.ch');
  assert.equal(firstParty.thirdParty, false);
  const main = makeEvent(details({ url: 'https://evil.example/', type: 'main_frame' }), 'strict', 'nzz.ch', 'ublock-badware')!;
  assert.equal(main.site, 'evil.example');
  assert.equal(main.list, 'ublock-badware');
  assert.equal(makeEvent(details({ url: 'data:text/plain,x' }), 'blocked', null), null);
  assert.equal(makeEvent(details({ url: `https://a.ch/${'x'.repeat(2000)}` }), 'blocked', null)!.url.length, 512);
});

test('history records never contain query or fragment', () => {
  const ev = makeEvent(details(), 'blocked', 'nzz.ch')!;
  assert.equal(historyRecord(ev).url, 'https://ads.doubleclick.net/x.js');
  assert.equal(ev.url, 'https://ads.doubleclick.net/x.js?a=1#f', 'original untouched');
});

test('daily aggregation, merging with negative deltas, top-N trimming', () => {
  const t = new Date(2026, 9, 18, 12).getTime();
  const evs: ActivityEvent[] = [
    makeEvent(details({ timeStamp: t }), 'blocked', 'nzz.ch')!,
    makeEvent(details({ timeStamp: t + 1, type: 'image', url: 'https://px.ads.net/p.gif' }), 'blocked', 'nzz.ch')!,
    makeEvent(details({ timeStamp: t + 2, url: 'https://shop.ch/?gclid=1', type: 'main_frame' }), 'stripped', null)!,
  ];
  evs[0].list = 'easylist';
  const aggs = aggregateEvents(evs, (e) => (e.list === 'easylist' ? 'ads' : 'unknown'));
  assert.equal(aggs.length, 1);
  const a = aggs[0];
  assert.equal(a.day, dayKey(t));
  assert.equal(a.day, '2026-10-18');
  assert.equal(a.total, 3);
  assert.deepEqual(a.byKind, { blocked: 2, stripped: 1 });
  assert.deepEqual(a.byCategory, { ads: 1, unknown: 2 });
  assert.deepEqual(a.byType, { script: 1, image: 1, main_frame: 1 });
  assert.deepEqual(a.bySite, { 'nzz.ch': 2, 'shop.ch': 1 });

  const delta: DailyAggregate = { ...emptyDaily(a.day), byCategory: { unknown: -1, privacy: 1 } };
  const merged = mergeDaily(a, delta);
  assert.deepEqual(merged.byCategory, { ads: 1, unknown: 1, privacy: 1 });
  assert.equal(merged.total, 3);
  const gone = mergeDaily(merged, { ...emptyDaily(a.day), byCategory: { privacy: -1 } });
  assert.equal(gone.byCategory.privacy, undefined);

  const big: Record<string, number> = {};
  for (let i = 0; i < 700; i++) big[`h${i}.ch`] = i;
  const top = trimTop(big);
  assert.equal(Object.keys(top).length, 500);
  assert.equal(top['h699.ch'], 699);
  assert.equal(top['h0.ch'], undefined);
  const agg = emptyDaily('2026-01-01');
  for (let i = 0; i < 600; i++) addEventToDaily(agg, { ...evs[0], host: `x${i}.ch` }, 'ads');
  assert.equal(Object.keys(mergeDaily(emptyDaily('2026-01-01'), agg).byHost).length, 500);
});

test('totals count prevented requests and survive bad stored data', () => {
  const t: Totals = emptyTotals(1);
  for (const kind of ['blocked', 'redirected', 'strict', 'stripped', 'debounced'] as const) bumpTotals(t, { ...makeEvent(details(), kind, null)!, kind });
  assert.equal(t.blocked, 3);
  assert.deepEqual(t.byKind, { blocked: 1, redirected: 1, strict: 1, stripped: 1, debounced: 1 });
  assert.deepEqual(sanitizeTotals({ since: 'x', blocked: -4, byKind: { blocked: 2, bogus: 9 } }, 5), { since: 5, blocked: 0, byKind: { blocked: 2 } });
});

test('attribution joins on tab and nearest timestamp, each match once', () => {
  const base = 1_700_000_000_000;
  const e1 = makeEvent(details({ timeStamp: base }), 'blocked', 'nzz.ch')!;
  const e2 = makeEvent(details({ timeStamp: base + 10 }), 'blocked', 'nzz.ch')!;
  const e3 = makeEvent(details({ timeStamp: base + 5000 }), 'blocked', 'nzz.ch')!;
  const other = makeEvent(details({ tabId: 99, timeStamp: base }), 'blocked', 'nzz.ch')!;
  const matches: MatchInfo[] = [
    { rule: { rulesetId: '_dynamic', ruleId: RULE_ID.GPC_HEADER }, tabId: 4, timeStamp: base },
    { rule: { rulesetId: 'easylist', ruleId: 12 }, tabId: 4, timeStamp: base + 8 },
    { rule: { rulesetId: 'easyprivacy', ruleId: 3 }, tabId: 4, timeStamp: base + 2 },
    { rule: { rulesetId: '_dynamic', ruleId: 5 }, tabId: 4, timeStamp: base + 4000 },
  ];
  const done = attributeEvents([e2, e1, e3, other], matches, { easylist: 'easylist', easyprivacy: 'easyprivacy' });
  assert.equal(done.length, 3);
  assert.equal(e1.rule, 'easyprivacy:3');
  assert.equal(e1.list, 'easyprivacy');
  assert.equal(e2.rule, 'easylist:12');
  assert.equal(e3.rule, '_dynamic:5');
  assert.equal(e3.list, 'custom');
  assert.equal(other.rule, undefined);
  assert.equal(listForRule('_dynamic', RULE_ID.ADMIN_START + 1, {}), 'admin');
  assert.equal(listForRule('_dynamic', RULE_ID.DEBOUNCE_START, {}), undefined);
});

test('badge text is compact', () => {
  assert.equal(badgeText(0), '');
  assert.equal(badgeText(7), '7');
  assert.equal(badgeText(999), '999');
  assert.equal(badgeText(4321), '4k');
  assert.equal(badgeText(123456), '9k+');
});

// --- service ---------------------------------------------------------------

interface Harness {
  svc: ActivityService;
  session: Map<string, unknown>;
  written: ActivityEvent[][];
  patched: { key: number; record: ActivityEvent }[][];
  badges: [number, string | null][];
  timers: (() => void)[];
  cfg: ActivityConfig;
  setNow(t: number): void;
  matches: MatchInfo[];
  runTimers(): Promise<void>;
}

function harness(over: Partial<ActivityConfig> = {}, badgeMode: BadgeMode = 'self'): Harness {
  const session = new Map<string, unknown>();
  const written: ActivityEvent[][] = [];
  const patched: { key: number; record: ActivityEvent }[][] = [];
  const badges: [number, string | null][] = [];
  const timers: (() => void)[] = [];
  let now = 1_700_000_000_000;
  let nextKey = 1;
  const matches: MatchInfo[] = [];
  const cfg: ActivityConfig = {
    activityLog: true,
    historyEnabled: true,
    badgeMode,
    rulesetToList: { easylist: 'easylist' },
    categoryOf: (id) => (id === 'easylist' ? 'ads' : 'unknown'),
    ...over,
  };
  const deps: ActivityDeps = {
    now: () => now,
    config: () => cfg,
    sessionGet: async (k) => session.get(k),
    sessionSet: async (items) => {
      for (const [k, v] of Object.entries(items)) session.set(k, structuredClone(v));
    },
    sessionRemove: async (keys) => {
      for (const k of keys) session.delete(k);
    },
    getMatchedRules: async () => matches,
    history: {
      write: async (records) => {
        written.push(records);
        return records.map(() => nextKey++);
      },
      patch: async (updates) => {
        patched.push(updates);
      },
    },
    loadTotals: async () => null,
    saveTotals: async () => undefined,
    setBadge: async (tabId, text) => {
      badges.push([tabId, text]);
    },
    setTimeout: (fn) => {
      timers.push(fn);
      return timers.length;
    },
  };
  const svc = new ActivityService(deps);
  return {
    svc,
    session,
    written,
    patched,
    badges,
    timers,
    cfg,
    matches,
    setNow: (t) => {
      now = t;
    },
    runTimers: async () => {
      for (let round = 0; round < 5 && timers.length > 0; round++) {
        const batch = timers.splice(0);
        for (const fn of batch) fn();
        await new Promise((r) => setTimeout(r, 0));
      }
    },
  };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

test('service: events flow to tab buffer, live ports, badge, history and totals', async () => {
  const h = harness();
  await h.svc.init();
  h.svc.onCommitted(4, 'https://www.nzz.ch/');
  const port = { got: [] as LivePortMessage[], postMessage(m: LivePortMessage) { this.got.push(m); } };
  h.svc.addPort(port);
  await h.svc.subscribe(port, 4);
  h.svc.onError({ ...details(), error: 'net::ERR_BLOCKED_BY_CLIENT' });
  h.svc.onError({ ...details(), error: 'net::ERR_CONNECTION_RESET' });
  h.svc.onRedirect({ ...details({ url: 'https://s.ch/p?gclid=1', type: 'sub_frame' }), redirectUrl: 'https://s.ch/p', statusCode: 307 });
  await flush();
  const summary = await h.svc.tabSummary(4);
  assert.deepEqual(summary.counts, { blocked: 1, redirected: 0, stripped: 1, debounced: 0, thirdPartyHosts: 2 });
  assert.equal(summary.recent.length, 2);
  assert.deepEqual(port.got.map((m) => m.type), ['backlog', 'event', 'event']);
  assert.equal(h.svc.getTotals().blocked, 1);

  await h.runTimers();
  assert.equal(h.written.length, 1);
  assert.equal(h.written[0][0].url, 'https://ads.doubleclick.net/x.js');
  assert.deepEqual(h.badges.at(-1), [4, '2']);
  const mirror = h.session.get('tab:4') as { events: ActivityEvent[]; site: string };
  assert.equal(mirror.site, 'nzz.ch');
  assert.equal(mirror.events.length, 2);

  // Navigation resets the page counters and tells live listeners.
  h.svc.onCommitted(4, 'https://www.srf.ch/');
  await flush();
  assert.deepEqual(port.got.at(-1), { type: 'reset', tabId: 4 });
  assert.equal((await h.svc.tabSummary(4)).counts.blocked, 0);
});

test('service: a restarted worker restores the tab from storage.session', async () => {
  const h = harness();
  await h.svc.init();
  h.svc.onCommitted(4, 'https://www.nzz.ch/');
  h.svc.onError({ ...details(), error: 'net::ERR_BLOCKED_BY_CLIENT' });
  await flush();
  await h.svc.flushMirror();
  const fresh = harness();
  for (const [k, v] of h.session) fresh.session.set(k, v);
  await fresh.svc.init();
  fresh.svc.onError({ ...details({ url: 'https://px.net/a.gif' }), error: 'net::ERR_BLOCKED_BY_CLIENT' });
  await flush();
  const s = await fresh.svc.tabSummary(4);
  assert.equal(s.counts.blocked, 2);
  assert.equal(s.recent.length, 2);
  assert.equal(s.recent[1].site, 'nzz.ch');
});

test('service: ring buffer is capped per tab', async () => {
  const h = harness({ historyEnabled: false });
  await h.svc.init();
  h.svc.onCommitted(1, 'https://a.ch/');
  for (let i = 0; i < LIVE_EVENTS_PER_TAB + 25; i++) h.svc.onError({ ...details({ tabId: 1, url: `https://x.net/${i}` }), error: 'net::ERR_BLOCKED_BY_CLIENT' });
  await flush();
  const s = await h.svc.tabSummary(1, 10_000);
  assert.equal(s.recent.length, LIVE_EVENTS_PER_TAB);
  assert.equal(s.recent.at(-1)!.url, `https://x.net/${LIVE_EVENTS_PER_TAB + 24}`);
  assert.equal(s.counts.blocked, LIVE_EVENTS_PER_TAB + 25);
});

test('service: activity log off records nothing but the self-maintained badge', async () => {
  const h = harness({ activityLog: false, historyEnabled: false });
  await h.svc.init();
  h.svc.onError({ ...details(), error: 'net::ERR_BLOCKED_BY_CLIENT' });
  await flush();
  await h.runTimers();
  assert.equal(h.written.length, 0);
  assert.equal((await h.svc.tabSummary(4)).recent.length, 0);
  assert.deepEqual(h.badges.at(-1), [4, '1']);
});

test('service: late attribution patches persisted history and category counts', async () => {
  const h = harness();
  await h.svc.init();
  h.svc.onCommitted(4, 'https://www.nzz.ch/');
  h.svc.onError({ ...details(), error: 'net::ERR_BLOCKED_BY_CLIENT' });
  await flush();
  await h.svc.flushHistory();
  assert.equal(h.written.length, 1);
  h.matches.push({ rule: { rulesetId: 'easylist', ruleId: 77 }, tabId: 4, timeStamp: details().timeStamp + 3 });
  h.setNow(details().timeStamp + 40_000);
  await h.svc.attribute();
  assert.equal(h.patched.length, 1);
  assert.equal(h.patched[0][0].key, 1);
  assert.equal(h.patched[0][0].record.list, 'easylist');
  assert.equal(h.patched[0][0].record.rule, 'easylist:77');
  // Quota guard: an immediate second call does not hit the API again.
  const before = h.patched.length;
  await h.svc.attribute();
  assert.equal(h.patched.length, before);
});

test('service: attribution that lands while a history write is in flight is patched afterwards', async () => {
  const h = harness();
  await h.svc.init();
  h.svc.onCommitted(4, 'https://www.nzz.ch/');
  h.svc.onError({ ...details(), error: 'net::ERR_BLOCKED_BY_CLIENT' });
  await flush();
  // Make the next history write wait until we release it.
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  const svcDeps = (h.svc as unknown as { deps: ActivityDeps }).deps;
  const originalWrite = svcDeps.history.write;
  svcDeps.history.write = async (records, deltas) => {
    await gate;
    return originalWrite(records, deltas);
  };
  const writing = h.svc.flushHistory();
  h.matches.push({ rule: { rulesetId: 'easylist', ruleId: 9 }, tabId: 4, timeStamp: details().timeStamp });
  h.setNow(details().timeStamp + 40_000);
  await h.svc.attribute();
  assert.equal(h.patched.length, 0, 'nothing persisted yet to patch');
  release();
  await writing;
  assert.equal(h.written[0][0].list, undefined, 'written before attribution');
  assert.equal(h.patched.length, 1);
  assert.equal(h.patched[0][0].record.rule, 'easylist:9');
});

test('service: leaving self badge mode resets tab texts', async () => {
  const h = harness();
  await h.svc.init();
  h.svc.onCommitted(4, 'https://www.nzz.ch/');
  await flush();
  h.svc.setBadgeMode('self');
  h.svc.setBadgeMode('browser');
  assert.deepEqual(h.badges.at(-1), [4, null]);
});

test('attribution falls back to tab -1, where Chromium moves a navigated-away page (UI-3)', () => {
  const base = 1_700_000_000_000;
  const left = makeEvent(details({ tabId: 5, timeStamp: base }), 'blocked', 'spiegel.de')!;
  const live = makeEvent(details({ tabId: 5, timeStamp: base + 9000 }), 'blocked', 'iana.org')!;
  const matches: MatchInfo[] = [
    { rule: { rulesetId: 'easyprivacy', ruleId: 4 }, tabId: -1, timeStamp: base + 1 },
    { rule: { rulesetId: 'easylist', ruleId: 8 }, tabId: 5, timeStamp: base + 9001 },
    // System rules in the -1 bucket are still ignored.
    { rule: { rulesetId: '_dynamic', ruleId: RULE_ID.GPC_HEADER }, tabId: -1, timeStamp: base },
  ];
  const done = attributeEvents([left, live], matches, { easylist: 'easylist', easyprivacy: 'easyprivacy' });
  assert.equal(done.length, 2);
  assert.equal(left.rule, 'easyprivacy:4');
  assert.equal(left.list, 'easyprivacy');
  assert.equal(live.rule, 'easylist:8');
  // The own tab is preferred; a -1 match is used once only.
  const again = makeEvent(details({ tabId: 6, timeStamp: base }), 'blocked', 'x.ch')!;
  assert.equal(attributeEvents([again], matches.slice(0, 1), { easyprivacy: 'easyprivacy' }).length, 1);
  const other = makeEvent(details({ tabId: 6, timeStamp: base + 60_000 }), 'blocked', 'x.ch')!;
  assert.equal(attributeEvents([other], matches.slice(0, 1), {}).length, 0, 'outside the time window');
});

test('service: redirected and debounced are counted apart; the badge counts both (UI-5)', async () => {
  const h = harness();
  await h.svc.init();
  h.svc.onCommitted(4, 'https://www.nzz.ch/');
  h.svc.onRedirect({ ...details({ url: 'https://ads.net/gpt.js' }), redirectUrl: `${EXT}/war/googletagservices_gpt.js` });
  h.svc.onRedirect({ ...details({ url: 'https://t.co/x', type: 'main_frame' }), redirectUrl: `${EXT}/pages/bounce.html?from=t.co#https%3A%2F%2Fa.ch` });
  await flush();
  const s = await h.svc.tabSummary(4);
  assert.equal(s.counts.redirected, 1);
  assert.equal(s.counts.debounced, 1);
  await h.runTimers();
  assert.deepEqual(h.badges.at(-1), [4, '2']);
});

test('service: the session mirror keeps counts, bounded hosts and 50 events without queries (SW-4)', async () => {
  const h = harness({ historyEnabled: false });
  await h.svc.init();
  h.svc.onCommitted(1, 'https://a.ch/');
  for (let i = 0; i < 120; i++) h.svc.onError({ ...details({ tabId: 1, url: `https://x${i}.net/p?id=${i}#f` }), error: 'net::ERR_BLOCKED_BY_CLIENT' });
  await flush();
  await h.svc.flushMirror();
  const m = h.session.get('tab:1') as { events: ActivityEvent[]; counts: Record<string, number>; tp: string[] };
  assert.equal(m.events.length, MIRROR_EVENTS);
  assert.ok(m.events.every((e) => !e.url.includes('?') && !e.url.includes('#')));
  assert.equal(m.events.at(-1)!.url, 'https://x119.net/p');
  assert.equal(m.counts.blocked, 120);
  assert.equal(m.tp.length, 120);
  assert.ok(MIRROR_TP_MAX >= 100);
  // The live buffer itself keeps full URLs.
  assert.equal((await h.svc.tabSummary(1, 1)).recent[0].url, 'https://x119.net/p?id=119#f');
});

test('service: a full storage.session keeps counts and hosts, drops events', async () => {
  const h = harness({ historyEnabled: false });
  const deps = (h.svc as unknown as { deps: ActivityDeps }).deps;
  let calls = 0;
  const original = deps.sessionSet;
  deps.sessionSet = async (items) => {
    calls++;
    if (calls === 1) throw new Error('QUOTA_BYTES quota exceeded');
    return original(items);
  };
  await h.svc.init();
  h.svc.onCommitted(2, 'https://a.ch/');
  h.svc.onError({ ...details({ tabId: 2 }), error: 'net::ERR_BLOCKED_BY_CLIENT' });
  await flush();
  calls = 0;
  await h.svc.flushMirror();
  const m = h.session.get('tab:2') as { events: ActivityEvent[]; counts: Record<string, number>; tp: string[] };
  assert.equal(m.events.length, 0);
  assert.equal(m.counts.blocked, 1);
  assert.deepEqual(m.tp, ['ads.doubleclick.net']);
});

test('service: badge-only path keeps no hostnames but its counts survive a restart (ENT-5)', async () => {
  const h = harness({ activityLog: false, historyEnabled: false });
  await h.svc.init();
  h.svc.onCommitted(4, 'https://www.nzz.ch/');
  h.svc.onError({ ...details(), error: 'net::ERR_BLOCKED_BY_CLIENT' });
  await flush();
  const s = await h.svc.tabSummary(4);
  assert.equal(s.counts.blocked, 1);
  assert.equal(s.counts.thirdPartyHosts, 0, 'no third-party host set without the activity log');
  await h.svc.flushMirror();
  const fresh = harness({ activityLog: false, historyEnabled: false });
  for (const [k, v] of h.session) fresh.session.set(k, v);
  await fresh.svc.init();
  assert.equal((await fresh.svc.tabSummary(4)).counts.blocked, 1);
});

test('service: late attribution is streamed as an "attributed" live message', async () => {
  const h = harness({ historyEnabled: false });
  await h.svc.init();
  h.svc.onCommitted(4, 'https://www.nzz.ch/');
  const port = { got: [] as LivePortMessage[], postMessage(m: LivePortMessage) { this.got.push(m); } };
  h.svc.addPort(port);
  await h.svc.subscribe(port, 4);
  h.svc.onError({ ...details(), error: 'net::ERR_BLOCKED_BY_CLIENT' });
  await flush();
  h.matches.push({ rule: { rulesetId: 'easylist', ruleId: 77 }, tabId: 4, timeStamp: details().timeStamp + 3 });
  h.setNow(details().timeStamp + 40_000);
  await h.svc.attribute();
  const msg = port.got.at(-1)!;
  assert.equal(msg.type, 'attributed');
  assert.deepEqual((msg as Extract<LivePortMessage, { type: 'attributed' }>).updates, [
    { t: details().timeStamp, tabId: 4, url: details().url, kind: 'blocked', list: 'easylist', rule: 'easylist:77' },
  ]);
});

test('service: own getMatchedRules polling backs off while the popup is open', async () => {
  const h = harness();
  let calls = 0;
  const deps = (h.svc as unknown as { deps: ActivityDeps }).deps;
  deps.getMatchedRules = async () => {
    calls++;
    return [];
  };
  await h.svc.init();
  h.svc.onCommitted(4, 'https://www.nzz.ch/');
  h.svc.onError({ ...details(), error: 'net::ERR_BLOCKED_BY_CLIENT' });
  await flush();
  const t0 = details().timeStamp + 40_000;
  h.setNow(t0);
  h.svc.notePopupQuery();
  await h.svc.attribute();
  assert.equal(calls, 0, 'paused after popup:state');
  h.setNow(t0 + POPUP_ATTRIBUTION_BACKOFF_MS - 1);
  await h.svc.attribute();
  assert.equal(calls, 0);
  h.setNow(t0 + POPUP_ATTRIBUTION_BACKOFF_MS);
  await h.svc.attribute();
  assert.equal(calls, 1);
  // Unattributed events are kept for the matched-rules horizon, not just 60 s.
  assert.ok(MATCHED_RULES_HORIZON_MS > 60_000);
});

test('service: incognito keeps totals in memory only', async () => {
  const h = harness({ persistTotals: false });
  let saved = 0;
  (h.svc as unknown as { deps: ActivityDeps }).deps.saveTotals = async () => {
    saved++;
  };
  await h.svc.init();
  h.svc.onError({ ...details(), error: 'net::ERR_BLOCKED_BY_CLIENT' });
  await flush();
  await h.runTimers();
  await h.svc.flushAll();
  assert.equal(saved, 0);
  assert.equal(h.svc.getTotals().blocked, 1);
});

test('incognito instance never persists history or totals', () => {
  assert.deepEqual(persistenceFor(defaultSettings(), false), { historyEnabled: true, keepEvents: true, persistTotals: true });
  assert.deepEqual(persistenceFor(defaultSettings(), true), { historyEnabled: false, keepEvents: true, persistTotals: false });
  assert.equal(persistenceFor(normalizeSettings({ ui: { activityLog: false } }), false).historyEnabled, false, 'no history without the log');
  assert.equal(persistenceFor(normalizeSettings({ history: { enabled: false } }), false).historyEnabled, false);
  assert.equal(persistenceFor(normalizeSettings({ history: { retentionDays: 0 } }), false).keepEvents, false);
});
