// Bastion Shield e2e — runtime features beyond the shipped lists: user custom
// network filters (block, @@ exception, $removeparam on same-site requests in
// Standard mode), per-site script blocking (chrome.contentSettings),
// bounce-tracking protection (debounce rules → pages/bounce.html → target
// site), and a settings change that wakes a stopped service worker (SW-1).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { PRIORITY, RULE_ID } from '../../../src/shared/constants.ts';
import type { CustomState } from '../../../src/shared/types.ts';
import type { StateSnapshot } from '../support/extension.ts';
import { expect, test } from '../support/fixtures.ts';
import { HOSTS } from '../support/hosts.ts';
import { describeResults, loadResources, poll } from '../support/pages.ts';
import { REPO_ROOT } from '../support/paths.ts';

test.describe('custom filters', () => {
  test.afterEach(async ({ ext }) => {
    await ext.sendAndApply({ type: 'custom:set', text: '' }, 3000);
  });

  test('user network filters block, and @@ exceptions override list blocks', async ({ page, server, ext }) => {
    const blockHost = 'custom-tracker.example.org';
    const allowPath = '/ddm/trackimp/bastion-allowed-1.gif';
    const text = [`||${blockHost}^`, `@@||ad.doubleclick.net${allowPath}$image,domain=${HOSTS.C}`].join('\n');
    const specs = [
      { url: server.url(blockHost, '/collect.js'), kind: 'script' as const, label: 'custom block' },
      { url: server.url('ad.doubleclick.net', allowPath), kind: 'img' as const, label: 'custom @@ exception' },
      { url: server.url('ad.doubleclick.net', '/ddm/trackimp/other.gif'), kind: 'img' as const, label: 'still list-blocked' },
    ];
    const before = await loadResources(page, server, HOSTS.C, specs, { title: 'no custom filters' });
    expect.soft(before[0].loaded, `custom host loads before the filter exists\n${describeResults(before)}`).toBe(true);
    expect.soft(before[1].blocked, `list blocks ad.doubleclick.net before the exception\n${describeResults(before)}`).toBe(true);

    const set = await ext.sendAndApply<{ error?: string }>({ type: 'custom:set', text });
    expect(set.response?.error, 'custom:set response').toBeUndefined();
    const state = await ext.send<CustomState>({ type: 'custom:get' });
    expect(state.report.errors, 'custom filters compile').toEqual([]);
    expect(state.report.network, 'two network rules').toBe(2);
    const dyn = (await ext.snapshot()).dynamicRules as { id: number }[];
    expect(dyn.filter((r) => r.id >= RULE_ID.CUSTOM_START && r.id <= RULE_ID.CUSTOM_END).length, 'custom rules in the user id range').toBeGreaterThanOrEqual(2);

    const after = await loadResources(page, server, HOSTS.C, specs, { title: 'with custom filters' });
    const msg = describeResults(after);
    expect.soft(after[0].blocked, `custom ||host^ blocks\n${msg}`).toBe(true);
    expect.soft(after[1].loaded, `custom @@ exception unblocks a list-blocked resource\n${msg}`).toBe(true);
    expect.soft(after[2].blocked, `exception is narrow: other paths stay blocked\n${msg}`).toBe(true);
    // $domain= scoping: the exception does not apply on another site.
    const elsewhere = await loadResources(page, server, HOSTS.A, [specs[1]], { title: 'exception out of scope' });
    expect.soft(elsewhere[0].blocked, `exception limited to ${HOSTS.C}\n${describeResults(elsewhere)}`).toBe(true);
  });

  test('Standard mode: a custom $removeparam also strips same-site subresources (MODIFIER_1P copy, BS-2)', async ({ page, server, ext }) => {
    const cfg = await ext.send<{ settings: { defaultMode: string } }>({ type: 'config:get' });
    expect(cfg.settings.defaultMode, 'runs in the default Standard mode').toBe('standard');
    const param = 'bxtrk';
    const text = [`||${HOSTS.A_SUB}^$removeparam=${param}`, `||${HOSTS.CDN}^$removeparam=${param}`].join('\n');
    const set = await ext.sendAndApply<{ error?: string }>({ type: 'custom:set', text });
    expect(set.response?.error, 'custom:set response').toBeUndefined();
    const state = await ext.send<CustomState>({ type: 'custom:get' });
    expect(state.report.errors, 'custom filters compile').toEqual([]);
    const dyn = (await ext.snapshot()).dynamicRules as { id: number; priority?: number; action: { type: string }; condition: { domainType?: string; resourceTypes?: string[] } }[];
    const copies = dyn.filter((r) => r.id >= RULE_ID.CUSTOM_START && r.id <= RULE_ID.CUSTOM_END && r.priority === PRIORITY.MODIFIER_1P);
    expect(copies.length, `first-party copies at priority ${PRIORITY.MODIFIER_1P}`).toBeGreaterThan(0);
    expect.soft(copies.every((r) => r.condition.domainType === 'firstParty' && !(r.condition.resourceTypes ?? []).includes('main_frame')), 'copies are firstParty, subresources only').toBe(true);

    const n = Date.now().toString(36);
    const specs = [
      { url: server.url(HOSTS.A_SUB, `/px/1p-${n}.gif?${param}=1&keep=a`), kind: 'img' as const, label: 'same-site subresource' },
      { url: server.url(HOSTS.CDN, `/px/3p-${n}.gif?${param}=1&keep=b`), kind: 'img' as const, label: 'third-party subresource' },
    ];
    const t0 = Date.now();
    await loadResources(page, server, HOSTS.A, specs, { title: 'removeparam' });
    const seen = (host: string, file: string) => server.hits.find((h) => h.t >= t0 && h.host === host && h.pathname === file);
    const sameSite = seen(HOSTS.A_SUB, `/px/1p-${n}.gif`);
    const thirdParty = seen(HOSTS.CDN, `/px/3p-${n}.gif`);
    console.log(`[removeparam] same-site query: ${sameSite?.query ?? '(no hit)'} | third-party query: ${thirdParty?.query ?? '(no hit)'}`);
    expect(sameSite, 'same-site request reached the server').toBeTruthy();
    expect(thirdParty, 'third-party request reached the server').toBeTruthy();
    expect.soft(new URLSearchParams(sameSite!.query).has(param), `${param} stripped on a same-site request despite the Standard first-party allow`).toBe(false);
    expect.soft(new URLSearchParams(sameSite!.query).get('keep'), 'other parameters kept').toBe('a');
    expect.soft(new URLSearchParams(thirdParty!.query).has(param), `${param} stripped on a third-party request`).toBe(false);
    expect.soft(new URLSearchParams(thirdParty!.query).get('keep'), 'other parameters kept').toBe('b');
  });
});

test.describe('per-site script blocking', () => {
  test.afterEach(async ({ ext }) => {
    await ext.sendAndApply({ type: 'sites:set', sites: {} }, 3000);
  });

  test('site:set blockScripts=true stops page scripts on that site only', async ({ page, server, ext }) => {
    const html = '<!doctype html><meta charset="utf-8"><title>static</title><script>document.title = "scripted";</script><p>js probe</p>';
    const urlC = server.setPage(HOSTS.C, '/e2e/js.html', html);
    const urlB = server.setPage(HOSTS.B, '/e2e/js.html', html);
    await page.goto(urlC);
    expect(await page.title(), 'scripts run by default').toBe('scripted');
    const r = await ext.sendAndApply<{ error?: string }>({ type: 'site:set', site: HOSTS.C, patch: { blockScripts: true } }, 4000);
    expect(r.response?.error, 'site:set response').toBeUndefined();
    await page.waitForTimeout(500); // contentSettings is not part of the DNR snapshot
    await page.goto(urlC);
    expect.soft(await page.title(), `scripts blocked on ${HOSTS.C}`).toBe('static');
    await page.goto(urlB);
    expect.soft(await page.title(), `scripts still run on ${HOSTS.B}`).toBe('scripted');
    await ext.sendAndApply({ type: 'site:set', site: HOSTS.C, patch: { blockScripts: false } }, 4000);
    await page.waitForTimeout(500);
    await page.goto(urlC);
    expect.soft(await page.title(), 'scripts run again after unblocking').toBe('scripted');
  });
});

interface DebounceRule {
  include: string[];
  exclude: string[];
  action: string;
  param: string;
  prepend_scheme?: string;
}

test.describe('debouncing', () => {
  test('bounce-tracking URLs skip the tracker and land on the target', async ({ page, server, ext, dist }) => {
    const rules = JSON.parse(readFileSync(path.join(REPO_ROOT, 'vendor', 'brave-lists', 'debounce.json'), 'utf8')) as DebounceRule[];
    // A plain "*://host/*" redirect rule whose host is not strict-blocked (that would win first).
    const pick = rules
      .filter((r) => r.action === 'redirect' && !r.prepend_scheme && r.include.length === 1 && /^\*:\/\/[a-z0-9.-]+\/\*$/.test(r.include[0]) && r.param)
      .map((r) => ({ host: r.include[0].slice(4, -2), param: r.param }))
      .find((r) => !dist.isStrictBlocked(r.host) && dist.rulesForHost(r.host).every((lr) => !(lr.rule.condition.resourceTypes ?? []).includes('main_frame')));
    test.skip(!pick, 'no simple debounce rule usable with the fixture server');
    const dyn = (await ext.snapshot()).dynamicRules as { id: number }[];
    expect(dyn.some((r) => r.id >= RULE_ID.DEBOUNCE_START && r.id <= RULE_ID.DEBOUNCE_END), 'debounce rules installed').toBe(true);

    const target = server.url(HOSTS.B, '/deal.html') + '?sku=42';
    const bounce = `https://${pick!.host}/click?${encodeURIComponent(pick!.param)}=${encodeURIComponent(target)}&cid=e2e`;
    const src = server.setPage(HOSTS.A, '/e2e/bounce-link.html', `<!doctype html><meta charset="utf-8"><title>bounce</title><a id="go" href="${bounce.replace(/&/g, '&amp;')}">deal</a>`);
    await page.goto(src);
    const t0 = Date.now();
    await Promise.all([page.waitForURL((u) => u.hostname === HOSTS.B, { timeout: 10_000 }).catch(() => {}), page.click('#go')]);
    const final = page.url();
    console.log(`[debounce] ${pick!.host} param=${pick!.param} -> ${final}`);
    expect(new URL(final).hostname, `bounce via ${pick!.host} lands on the target`).toBe(HOSTS.B);
    expect.soft(new URL(final).searchParams.get('sku'), 'target query preserved').toBe('42');
    expect.soft(server.hits.filter((h) => h.t >= t0 && h.host === pick!.host).length, `the bounce tracker ${pick!.host} was never contacted`).toBe(0);
  });
});

test.describe('service worker wake-up (SW-1)', () => {
  type Rule = { id: number };
  const hasGpc = (s: StateSnapshot) => (s.dynamicRules as Rule[]).some((r) => r.id === RULE_ID.GPC_HEADER);

  test('a settings change that starts a stopped service worker reaches DNR', async ({ ext }) => {
    const listId = 'easylist';
    const prev = (await ext.api(async () => ((await chrome.storage.local.get('settings')) as Record<string, unknown>).settings ?? null)) as Record<string, unknown> | null;
    const before = await ext.snapshot();
    expect(before.enabledRulesets, `${listId} enabled before`).toContain(listId);
    expect(hasGpc(before), 'GPC header rule installed before').toBe(true);

    // Stopped worker + a write from another trusted context (dashboard, backup
    // restore, a second window): the event that wakes the worker carries the change.
    expect(await ext.stopServiceWorker(), 'service worker stopped').toBe(true);
    await ext.api(async (p: Record<string, unknown> | null) => {
      const base = (p ?? { version: 1 }) as { lists?: Record<string, boolean>; privacy?: Record<string, unknown> };
      await chrome.storage.local.set({ settings: { ...base, lists: { ...(base.lists ?? {}), easylist: false }, privacy: { ...(base.privacy ?? {}), gpc: false } } });
    }, prev);
    const off = await poll(() => ext.snapshot(), (s) => !s.enabledRulesets.includes(listId) && !hasGpc(s), 5000, 150);
    expect(off.enabledRulesets, `${listId} disabled within 5 s of the wake-up write`).not.toContain(listId);
    expect(hasGpc(off), 'GPC header rule removed within 5 s').toBe(false);

    // Restore through the same cold path.
    expect(await ext.stopServiceWorker(), 'service worker stopped again').toBe(true);
    await ext.api(async (p: Record<string, unknown> | null) => {
      if (p === null) await chrome.storage.local.remove('settings');
      else await chrome.storage.local.set({ settings: p });
    }, prev);
    const on = await poll(() => ext.snapshot(), (s) => s.enabledRulesets.includes(listId) && hasGpc(s), 5000, 150);
    expect(on.enabledRulesets, `${listId} enabled again`).toContain(listId);
    expect(hasGpc(on), 'GPC header rule back').toBe(true);
  });
});
