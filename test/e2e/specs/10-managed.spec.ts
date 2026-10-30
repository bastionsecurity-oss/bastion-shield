// Bastion Shield e2e — managed policy in a real browser: the fleet kill switch
// (protectionEnabled: false) and lockSettings. chrome.storage.managed cannot
// be written from a test, so this spec runs its own browser with a staged
// build whose service worker reads a simulated policy (support/managed.ts);
// policy changes reach the shipped code through storage.onChanged('managed'),
// as a real Intune/GPO push does.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { Page } from '@playwright/test';
import { RULE_ID } from '../../../src/shared/constants.ts';
import type { CustomState, EffectiveConfig, ListsState, PopupState, SitesMap } from '../../../src/shared/types.ts';
import { expect, test } from '../support/fixtures.ts';
import { ExtensionHarness } from '../support/extension.ts';
import type { StateSnapshot } from '../support/extension.ts';
import { HOSTS, KNOWN_TRACKERS } from '../support/hosts.ts';
import { setManagedPolicy } from '../support/managed.ts';
import { describeResults, loadResources, poll } from '../support/pages.ts';
import type { ResSpec } from '../support/pages.ts';
import { elementHtml, pickGenericSelectors } from '../support/pickers.ts';

type Rule = { id: number; action: { type: string }; condition: { requestDomains?: string[]; resourceTypes?: string[]; tabIds?: number[] } };

let mx: ExtensionHarness;

test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ server }) => {
  test.setTimeout(90_000);
  mx = await ExtensionHarness.launch({ port: server.port, managedShim: true });
  const r = await mx.waitUntilReady(20_000);
  expect(r.ready, 'install-time apply finished in the managed-shim browser').toBe(true);
});

test.afterAll(async () => {
  await mx?.close();
});

/** Push a policy and wait until DNR/registration state settled. */
async function pushPolicy(policy: Record<string, unknown>, until: (s: StateSnapshot) => boolean): Promise<StateSnapshot> {
  const sw = await mx.sw();
  const r = await setManagedPolicy(sw, policy);
  expect(r.patched, 'chrome.storage.managed.get is simulated in the service worker').toBe(true);
  expect(r.listeners, 'the service worker registered a storage.onChanged listener').toBeGreaterThan(0);
  const snap = await poll(() => mx.snapshot(), until, 8000, 150);
  await new Promise((res) => setTimeout(res, 300));
  return snap;
}

const isGlobalOff = (s: StateSnapshot) =>
  (s.dynamicRules as Rule[]).some((r) => r.id === RULE_ID.SITES_DISABLED && r.action.type === 'allowAllRequests' && !r.condition.requestDomains) && s.scripts.length === 0;
const isNormal = (s: StateSnapshot) => (s.dynamicRules as Rule[]).some((r) => r.id === RULE_ID.STANDARD_1P_ALLOW) && s.scripts.length > 0;

async function withPage<T>(fn: (p: Page) => Promise<T>): Promise<T> {
  const p = await mx.context.newPage();
  try {
    return await fn(p);
  } finally {
    await p.close().catch(() => {});
  }
}

test.describe('managed policy', () => {
  test('kill switch: protectionEnabled=false turns protection off everywhere and back on', async ({ server, dist }) => {
    const specs: ResSpec[] = KNOWN_TRACKERS.map((t) => ({ url: server.url(t.host, t.path), kind: t.kind, label: t.host }));
    const generic = pickGenericSelectors(dist, 1)[0];
    // A third-party creative inside, so Standard mode keeps the box hidden (an empty one is un-hidden, 04c-unhide).
    const adBox = generic ? elementHtml(generic.element, 'generic', '').replace('></', `><img src="https://${HOSTS.CDN}/creative/banner.gif" alt=""></`) : '';
    const probeHtml = generic ? `<!doctype html><meta charset="utf-8"><title>kill switch</title>${adBox}` : '';
    const probeDisplay = (n: number) =>
      withPage(async (pg) => {
        const url = server.setPage(HOSTS.A, `/e2e/kill-cosmetic-${n}.html`, probeHtml);
        await pg.goto(url);
        await pg.waitForTimeout(800);
        return pg.locator('[data-bx-probe="generic"]').evaluate((e) => getComputedStyle(e).display);
      });

    const before = await withPage((p) => loadResources(p, server, HOSTS.A, specs, { title: 'policy: protection on' }));
    const blockedBefore = before.filter((r) => r.blocked).length;
    expect(blockedBefore, `trackers blocked before the kill switch\n${describeResults(before)}`).toBeGreaterThan(0);
    if (generic) expect.soft(await probeDisplay(1), `generic selector ${generic.selector} applies while protection is on`).toBe('none');

    // Switch protection off fleet-wide.
    const off = await pushPolicy({ protectionEnabled: false, organizationName: 'Bastion e2e' }, isGlobalOff);
    expect(isGlobalOff(off), `global allowAllRequests and no content scripts\n${JSON.stringify(off.dynamicRules)}\nscripts=${off.scripts.length}`).toBe(true);
    const others = (off.dynamicRules as Rule[]).filter((r) => r.id !== RULE_ID.SITES_DISABLED);
    expect.soft(others.map((r) => r.id), 'custom, Standard, GPC and debounce rules are removed while the switch is off').toEqual([]);
    expect.soft((off.sessionRules as Rule[]).some((r) => r.id === RULE_ID.SESSION_SITES_DISABLED_NO_TAB && (r.condition.tabIds ?? []).includes(-1)), 'tabId -1 session allow').toBe(true);

    const offRes = await withPage((p) => loadResources(p, server, HOSTS.A, specs, { title: 'policy: protection off' }));
    for (const r of offRes) expect.soft(r.loaded, `kill switch: ${r.label} loads\n${describeResults(offRes)}`).toBe(true);
    const offB = await withPage((p) => loadResources(p, server, HOSTS.B, specs.slice(0, 2), { title: 'policy: protection off (other site)' }));
    for (const r of offB) expect.soft(r.loaded, `kill switch applies on every site: ${r.label}\n${describeResults(offB)}`).toBe(true);
    if (generic) expect.soft(await probeDisplay(2), 'no cosmetic filtering while the kill switch is on').not.toBe('none');

    const state = await withPage(async (p) => {
      await p.goto(server.setPage(HOSTS.A, '/e2e/kill-popup.html', '<!doctype html><title>popup</title><p>x</p>'));
      const tabId = await mx.tabIdOf(p);
      return mx.send<PopupState & { error?: string }>({ type: 'popup:state', tabId });
    });
    expect(state.error, 'popup:state response').toBeUndefined();
    expect.soft(state.globallyDisabled, 'popup:state.globallyDisabled').toBe(true);
    const cfg = await mx.send<EffectiveConfig>({ type: 'config:get' });
    expect.soft(cfg.managed.protectionEnabled, 'config:get reports the policy').toBe(false);

    // A worker restart keeps the switch (the policy is re-read on start).
    expect.soft(await mx.stopServiceWorker(), 'service worker stopped').toBe(true);
    const woken = await mx.send<EffectiveConfig>({ type: 'config:get' });
    expect.soft(woken.managed.protectionEnabled, 'policy re-read after a worker restart').toBe(false);
    const restarted = await poll(() => mx.snapshot(), isGlobalOff, 3000, 200);
    expect.soft(isGlobalOff(restarted), `still off after a worker restart\nscripts=${restarted.scripts.length}`).toBe(true);

    // Policy removed: everything comes back.
    const on = await pushPolicy({}, isNormal);
    expect(isNormal(on), `Standard rule and content scripts restored\nscripts=${on.scripts.length}`).toBe(true);
    expect.soft((on.dynamicRules as Rule[]).some((r) => r.id === RULE_ID.GPC_HEADER), 'GPC header rule restored').toBe(true);
    expect.soft((on.dynamicRules as Rule[]).some((r) => r.id === RULE_ID.SITES_DISABLED), 'no protection-off rule left').toBe(false);
    const after = await withPage((p) => loadResources(p, server, HOSTS.A, specs, { title: 'policy: protection on again' }));
    expect(after.filter((r) => r.blocked).length, `blocked again after the policy is removed\n${describeResults(after)}`).toBe(blockedBefore);
    if (generic) expect.soft(await probeDisplay(3), 'cosmetic filtering is back').toBe('none');
  });

  test('lockSettings: settings, lists, site rows and user filters are read-only; lockLists/allowUserFilters reopen them', async () => {
    const baseCfg = await mx.send<EffectiveConfig>({ type: 'config:get' });
    // Without a policy only catalog-locked lists (lists.bastion) are locked.
    for (const p of ['defaultMode', 'lists', 'customFilters']) expect(baseCfg.locked, `${p} not locked without a policy`).not.toContain(p);
    const listId = 'easylist';

    await pushPolicy({ lockSettings: true }, () => true);
    const cfg = await poll(
      () => mx.send<EffectiveConfig>({ type: 'config:get' }),
      (c) => c.managed.lockSettings === true,
      5000,
    );
    expect(cfg.managed.lockSettings, 'policy reached the service worker').toBe(true);
    for (const p of ['defaultMode', 'privacy.gpc', 'lists', 'customFilters']) expect.soft(cfg.locked, `locked path ${p}`).toContain(p);

    const set = await mx.send<EffectiveConfig & { ignored: string[]; error?: string }>({ type: 'settings:set', patch: { defaultMode: 'aggressive', privacy: { gpc: false } } });
    expect(set.error, 'settings:set answers with the config').toBeUndefined();
    expect.soft(set.ignored, 'settings:set reports the ignored paths').toEqual(expect.arrayContaining(['defaultMode', 'privacy.gpc']));
    expect.soft(set.settings.defaultMode, 'defaultMode unchanged').toBe(baseCfg.settings.defaultMode);
    expect.soft(set.settings.privacy.gpc, 'gpc unchanged').toBe(baseCfg.settings.privacy.gpc);

    const lists = await mx.send<ListsState & { error?: string }>({ type: 'lists:set', listId, enabled: false });
    expect.soft(lists.error, 'lists:set is refused').toBe('locked');
    const lg = await mx.send<ListsState>({ type: 'lists:get' });
    expect.soft(lg.locked, 'lists:get marks every list locked').toContain(listId);
    expect.soft((await mx.snapshot()).enabledRulesets, 'ruleset still enabled').toContain(listId);

    const sites = await mx.send<{ sites?: SitesMap; error?: string }>({ type: 'sites:set', sites: { [HOSTS.C]: { mode: 'aggressive' } } });
    expect.soft(sites.error, 'sites:set is refused').toBe('locked');
    const site = await mx.send<{ ok?: boolean; ignored: string[]; error?: string }>({ type: 'site:set', site: HOSTS.C, patch: { mode: 'aggressive', blockScripts: true } });
    expect.soft(site.error, 'site:set answers').toBeUndefined();
    expect.soft(site.ignored, 'site:set drops mode and blockScripts').toEqual(expect.arrayContaining(['mode', 'blockScripts']));
    const sg = await mx.send<{ sites: SitesMap }>({ type: 'sites:get' });
    expect.soft(sg.sites[HOSTS.C]?.mode, 'no per-site mode stored').toBeUndefined();

    const custom = await mx.send<CustomState & { error?: string }>({ type: 'custom:set', text: '||locked-filter.example.org^' });
    expect.soft(custom.error, 'custom:set is refused').toBe('locked');
    const cg = await mx.send<CustomState>({ type: 'custom:get' });
    expect.soft(cg.locked, 'custom:get reports locked').toBe(true);
    expect.soft(cg.text, 'user filters unchanged').toBe('');

    // Explicit exceptions in the policy reopen lists and user filters.
    await pushPolicy({ lockSettings: true, lockLists: false, allowUserFilters: true }, () => true);
    const cfg2 = await poll(
      () => mx.send<EffectiveConfig>({ type: 'config:get' }),
      (c) => c.managed.lockLists === false,
      5000,
    );
    expect.soft(cfg2.locked, 'defaultMode stays locked').toContain('defaultMode');
    expect.soft(cfg2.locked, "'lists' unlocked by lockLists:false").not.toContain('lists');
    expect.soft(cfg2.locked, "'customFilters' unlocked by allowUserFilters:true").not.toContain('customFilters');
    const before = await mx.snapshot();
    const lists2 = await mx.send<ListsState & { error?: string }>({ type: 'lists:set', listId, enabled: false });
    expect.soft(lists2.error, 'lists:set allowed with lockLists:false').toBeUndefined();
    await mx.waitForApply(before, 6000);
    expect.soft((await mx.snapshot()).enabledRulesets, 'list switched off').not.toContain(listId);
    const lists3 = await mx.send<ListsState & { error?: string }>({ type: 'lists:set', listId, enabled: true });
    expect.soft(lists3.error, 'list switched back on').toBeUndefined();
    const custom2 = await mx.send<CustomState & { error?: string }>({ type: 'custom:set', text: '' });
    expect.soft(custom2.error, 'custom:set allowed with allowUserFilters:true').toBeUndefined();

    await pushPolicy({}, () => true);
    const cfg3 = await poll(() => mx.send<EffectiveConfig>({ type: 'config:get' }), (c) => c.locked.length === baseCfg.locked.length, 5000);
    expect(cfg3.locked.sort(), 'policy removed: back to the catalog locks only').toEqual([...baseCfg.locked].sort());
    await poll(() => mx.snapshot(), (s) => s.enabledRulesets.includes(listId), 5000);
  });
});
