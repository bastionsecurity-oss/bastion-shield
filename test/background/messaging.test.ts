// Tests for message handlers (src/background/messaging.ts) and the
// strict-block proceed flow (src/background/blocked.ts) against in-memory
// chrome.* fakes.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PRIORITY, RULE_ID } from '../../src/shared/constants.ts';
import type { ManagedPolicy, Message, PopupState, SitesMap } from '../../src/shared/types.ts';
import { ActivityService } from '../../src/background/activity.ts';
import type { MatchInfo } from '../../src/background/activity.ts';
import { emptyReport } from '../../src/background/apply.ts';
import type { Applier } from '../../src/background/apply.ts';
import { BlockedPages, SESSION_RECORDS_KEY } from '../../src/background/blocked.ts';
import { EMPTY_COMPILED } from '../../src/background/custom.ts';
import type { CustomCompiled } from '../../src/background/custom.ts';
import { activityFlags, handleMessage, planSiteSet, reportBrokenSiteFor, userSitesFromInput } from '../../src/background/messaging.ts';
import type { MessageContext } from '../../src/background/messaging.ts';
import { defaultSettings, normalizeSettings } from '../../src/background/settings.ts';
import { Store } from '../../src/background/store.ts';

interface Fake {
  local: Map<string, unknown>;
  session: Map<string, unknown>;
  managed: ManagedPolicy;
  sessionRules: chrome.declarativeNetRequest.Rule[];
  navigations: { tabId: number; url: string }[];
  tabUrl: string;
}

function installChrome(managed: ManagedPolicy = {}): Fake {
  const fake: Fake = { local: new Map(), session: new Map(), managed, sessionRules: [], navigations: [], tabUrl: 'https://www.example.org/' };
  const area = (m: Map<string, unknown>) => ({
    get: async (keys: string[] | string | null) => {
      const out: Record<string, unknown> = {};
      const list = keys === null ? Array.from(m.keys()) : Array.isArray(keys) ? keys : [keys];
      for (const k of list) if (m.has(k)) out[k] = structuredClone(m.get(k));
      return out;
    },
    set: async (items: Record<string, unknown>) => {
      for (const [k, v] of Object.entries(items)) m.set(k, structuredClone(v));
    },
    remove: async (keys: string | string[]) => {
      for (const k of Array.isArray(keys) ? keys : [keys]) m.delete(k);
    },
  });
  (globalThis as unknown as { chrome: unknown }).chrome = {
    storage: { local: area(fake.local), session: area(fake.session), managed: { get: async () => structuredClone(fake.managed) } },
    declarativeNetRequest: {
      getSessionRules: async () => structuredClone(fake.sessionRules),
      updateSessionRules: async (u: { removeRuleIds?: number[]; addRules?: chrome.declarativeNetRequest.Rule[] }) => {
        fake.sessionRules = fake.sessionRules.filter((r) => !(u.removeRuleIds ?? []).includes(r.id));
        fake.sessionRules.push(...(u.addRules ?? []));
      },
    },
    tabs: {
      get: async (tabId: number) => ({ id: tabId, url: fake.tabUrl }),
      update: async (tabId: number, p: { url: string }) => {
        fake.navigations.push({ tabId, url: p.url });
        return {};
      },
    },
    i18n: { getUILanguage: () => 'de-CH' },
    runtime: { getManifest: () => ({ version: '1.2.3' }) },
  };
  return fake;
}

async function context(
  managed: ManagedPolicy = {},
  sites: SitesMap = {},
): Promise<{ ctx: MessageContext; fake: Fake; applied: () => number; matchedCalls: () => number }> {
  const fake = installChrome(managed);
  fake.local.set('sites', sites);
  const store = new Store();
  await store.load(null);
  let runs = 0;
  const applier: Applier = {
    schedule: async () => {
      runs++;
    },
    now: async () => {
      runs++;
    },
    report: () => emptyReport(),
    restoreReport: async () => undefined,
  };
  const custom: CustomCompiled = { user: EMPTY_COMPILED, admin: EMPTY_COMPILED, cosmetic: { specific: [], generic: [] }, genericHideHosts: [] };
  let matchedCalls = 0;
  const activity = new ActivityService({
    now: () => Date.now(),
    config: () => ({ activityLog: true, historyEnabled: false, badgeMode: 'self', rulesetToList: {}, categoryOf: () => 'unknown' }),
    sessionGet: async () => undefined,
    sessionSet: async () => undefined,
    sessionRemove: async () => undefined,
    getMatchedRules: async (): Promise<MatchInfo[]> => {
      matchedCalls++;
      return [];
    },
    history: { write: async () => [], patch: async () => undefined },
    loadTotals: async () => null,
    saveTotals: async () => undefined,
    setBadge: async () => undefined,
    setTimeout: () => 0,
  });
  await activity.init();
  const ctx = {
    store,
    applier,
    activity,
    blocked: new BlockedPages({ meta: () => null, resourceTypes: () => ['main_frame', 'sub_frame', 'script'] }),
    custom: () => custom,
    recompileCustom: () => undefined,
    pruneHistory: async () => undefined,
  } as unknown as MessageContext;
  return { ctx, fake, applied: () => runs, matchedCalls: () => matchedCalls };
}

const send = (ctx: MessageContext, msg: unknown, sender = {}) => handleMessage(ctx, msg as Message, sender);

// --- site:set ----------------------------------------------------------------

test('site:set: switching a site off and on again leaves no phantom exception (UI-8)', () => {
  const s = defaultSettings();
  const off = planSiteSet({}, '20min.ch', { enabled: false }, {}, s, { enabled: false, mode: false });
  assert.deepEqual(off.sites, { '20min.ch': { enabled: false } });
  const on = planSiteSet(off.sites, '20min.ch', { enabled: true }, {}, s, { enabled: false, mode: false });
  assert.deepEqual(on.sites, {});
  // Below a disabled parent the explicit `true` is a real exception and stays.
  const child = planSiteSet({ 'example.com': { enabled: false } }, 'shop.example.com', { enabled: true }, {}, s, { enabled: false, mode: false });
  assert.deepEqual(child.sites['shop.example.com'], { enabled: true });
  // Other fields of the entry are kept.
  const both = planSiteSet({ 'x.ch': { enabled: false, blockScripts: true } }, 'x.ch', { enabled: true }, {}, s, { enabled: false, mode: false });
  assert.deepEqual(both.sites, { 'x.ch': { blockScripts: true } });
});

test('site:set: lockSettings locks per-site mode, scripts and fingerprinting (ENT-2)', () => {
  const r = planSiteSet({}, 'x.ch', { mode: 'aggressive', blockScripts: true, fingerprinting: 'strict', enabled: false }, { lockSettings: true }, defaultSettings(), {
    enabled: false,
    mode: false,
  });
  assert.deepEqual(r.ignored.sort(), ['blockScripts', 'fingerprinting', 'mode']);
  assert.deepEqual(r.sites, { 'x.ch': { enabled: false } }, 'the protection switch follows allowUserSiteToggle');
});

test('site:set: mode is locked below an aggressiveSites host (ENT-4)', async () => {
  const { ctx } = await context({ aggressiveSites: ['example.com'] });
  const res = (await send(ctx, { type: 'site:set', site: 'shop.example.com', patch: { mode: 'standard' } })) as { ignored: string[]; siteSettings: { mode: string } };
  assert.deepEqual(res.ignored, ['mode']);
  assert.equal(res.siteSettings.mode, 'aggressive');
  assert.deepEqual(ctx.store.sites, {});
});

// --- sites:get / sites:set -----------------------------------------------------

test('sites:get returns the user map; sites:set never stores policy overlays (SW-2)', async () => {
  const { ctx, fake } = await context({ disabledSites: ['crm.example.ch'], aggressiveSites: ['news.example.com'] }, { 'shop.example.org': { blockScripts: true } });
  const got = (await send(ctx, { type: 'sites:get' })) as { sites: SitesMap };
  assert.deepEqual(got, { sites: { 'shop.example.org': { blockScripts: true } } });
  // An old dashboard posts the effective map back with one unrelated edit.
  const res = (await send(ctx, {
    type: 'sites:set',
    sites: { 'crm.example.ch': { enabled: false }, 'news.example.com': { mode: 'aggressive' }, 'shop.example.org': { blockScripts: false } },
  })) as { sites: SitesMap };
  assert.deepEqual(res, { sites: { 'shop.example.org': { blockScripts: false } } });
  assert.deepEqual(fake.local.get('sites'), { 'shop.example.org': { blockScripts: false } });
  // Once the admin removes the policy entries, nothing sticks.
  fake.managed = {};
  await ctx.store.reloadManaged();
  assert.equal(ctx.store.effectiveSites()['crm.example.ch'], undefined);
  assert.equal(ctx.store.effectiveSites()['news.example.com'], undefined);
});

test('sites:set and custom filters are locked under lockSettings (ENT-2)', async () => {
  const { ctx, applied } = await context({ lockSettings: true });
  assert.deepEqual(await send(ctx, { type: 'sites:set', sites: { 'a.ch': { mode: 'aggressive' } } }), { error: 'locked' });
  assert.equal(applied(), 0);
  const custom = (await send(ctx, { type: 'custom:get' })) as { locked: boolean };
  assert.equal(custom.locked, true);
  assert.deepEqual(await send(ctx, { type: 'custom:set', text: '||x^' }), { error: 'locked' });
  const open = await context({ lockSettings: true, allowUserFilters: true });
  assert.equal(((await send(open.ctx, { type: 'custom:get' })) as { locked: boolean }).locked, false);
});

test('backup sites keep policy-owned fields', () => {
  const next = userSitesFromInput({ 'crm.example.ch': { enabled: false }, 'WWW.A.CH': { mode: 'aggressive' } }, {}, { disabledSites: ['crm.example.ch'] });
  assert.deepEqual(next, { 'a.ch': { mode: 'aggressive' } });
});

// --- popup state helpers ---------------------------------------------------------

test('popup: report target defaults to the managed helpdesk (UI-4)', () => {
  assert.equal(reportBrokenSiteFor({}), 'github');
  assert.equal(reportBrokenSiteFor({ supportEmail: 'it@muster.ch' }), 'email');
  assert.equal(reportBrokenSiteFor({ supportEmail: 'it@muster.ch', reportBrokenSite: 'none' }), 'none');
  assert.equal(reportBrokenSiteFor({ reportBrokenSite: 'github', supportEmail: 'it@muster.ch' }), 'github');
});

test('popup: logging and counting flags (UI-1)', () => {
  assert.deepEqual(activityFlags(defaultSettings()), { logging: true, counting: true });
  assert.deepEqual(activityFlags(normalizeSettings({ ui: { activityLog: false } })), { logging: false, counting: true }, 'GPC on: SW badge counts');
  assert.deepEqual(activityFlags(normalizeSettings({ ui: { activityLog: false }, privacy: { gpc: false } })), { logging: false, counting: false });
  assert.deepEqual(activityFlags(normalizeSettings({ ui: { activityLog: false, badge: false } })), { logging: false, counting: false });
});

test('popup:state carries kill switch, mode lock, debounced count and activity flags', async () => {
  const { ctx, fake, matchedCalls } = await context({
    aggressiveSites: ['example.com'],
    protectionEnabled: false,
    supportEmail: 'it@muster.ch',
    organizationName: 'Muster AG',
  });
  fake.tabUrl = 'https://shop.example.com/warenkorb';
  const ext = 'chrome-extension://0123456789abcdef0123456789abcdef';
  const t = Date.now();
  ctx.activity.onCommitted(5, fake.tabUrl);
  ctx.activity.onError({ tabId: 5, frameId: 0, url: 'https://ads.tracker.net/p.gif', type: 'image', timeStamp: t, error: 'net::ERR_BLOCKED_BY_CLIENT' });
  ctx.activity.onRedirect({ tabId: 5, frameId: 0, url: 'https://t.co/x?u=1', type: 'main_frame', timeStamp: t, redirectUrl: `${ext}/pages/bounce.html?from=t.co#https%3A%2F%2Fa.ch` });
  ctx.activity.onRedirect({ tabId: 5, frameId: 0, url: 'https://ads.net/gpt.js', type: 'script', timeStamp: t, redirectUrl: `${ext}/war/noop.js` });
  const s = (await send(ctx, { type: 'popup:state', tabId: 5 })) as PopupState;
  assert.equal(s.site, 'shop.example.com');
  assert.equal(s.globallyDisabled, true);
  assert.deepEqual(s.locks, { siteToggle: false, mode: true, settings: false });
  assert.equal(s.siteSettings.mode, 'aggressive');
  assert.deepEqual(s.counts, { blocked: 1, redirected: 1, stripped: 0, debounced: 1, thirdPartyHosts: 2 }, 'a main_frame bounce is first party to itself');
  assert.equal(s.logging, true);
  assert.equal(s.counting, true);
  assert.deepEqual(s.managed, { organizationName: 'Muster AG', reportBrokenSite: 'email', supportEmail: 'it@muster.ch', supportUrl: undefined });
  // The popup calls getMatchedRules itself: our own polling stays off for now.
  await ctx.activity.attribute();
  assert.equal(matchedCalls(), 0);
});

// --- strict block: proceed ---------------------------------------------------------

test('proceed only to the host blocked in that tab, with a host-scoped allow (SEC-2)', async () => {
  const { ctx, fake } = await context();
  const blocked = ctx.blocked;
  // No record: refused (a compromised frame cannot allowlist arbitrary hosts).
  assert.deepEqual(await blocked.proceed(7, 'https://1980s.click/'), { error: 'no blocked navigation' });
  blocked.record(7, 'https://evil.example/landing?x=1', 'ublock-badware');
  assert.deepEqual(await blocked.proceed(7, 'https://1980s.click/'), { error: 'url does not match the blocked navigation' });
  assert.deepEqual(await blocked.proceed(8, 'https://evil.example/landing?x=1'), { error: 'no blocked navigation' }, 'other tab');
  assert.equal(fake.sessionRules.length, 0);
  assert.deepEqual(await blocked.proceed(7, 'https://evil.example/landing?x=1'), { ok: true });
  assert.deepEqual(fake.sessionRules, [
    {
      id: RULE_ID.SESSION_PROCEED_START,
      priority: PRIORITY.PROCEED_ANYWAY,
      action: { type: 'allow' },
      condition: { requestDomains: ['evil.example'], tabIds: [7], resourceTypes: ['main_frame', 'sub_frame', 'script'] },
    },
  ]);
  assert.deepEqual(fake.navigations, [{ tabId: 7, url: 'https://evil.example/landing?x=1' }]);
  // The record is used up.
  assert.deepEqual(await blocked.proceed(7, 'https://evil.example/landing?x=1'), { error: 'no blocked navigation' });
});

test('blocked records survive a worker restart and are forgotten on the next commit', async () => {
  const { ctx, fake } = await context();
  ctx.blocked.record(3, 'https://evil.example/', null as unknown as undefined);
  await new Promise((r) => setTimeout(r, 0));
  await new Promise((r) => setTimeout(r, 0));
  assert.ok((fake.session.get(SESSION_RECORDS_KEY) as Record<string, unknown>)['3']);
  const fresh = new BlockedPages({ meta: () => null, resourceTypes: () => [] });
  await fresh.restore();
  assert.equal(fresh.hasRecords(), true);
  assert.equal((await fresh.info(3, undefined)).host, 'evil.example');
  fresh.forget(3);
  assert.equal(fresh.hasRecords(), false);
  assert.equal((await fresh.info(3, undefined)).url, null, 'stale record no longer leaks the URL');
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(fake.session.get(SESSION_RECORDS_KEY), {});
});
