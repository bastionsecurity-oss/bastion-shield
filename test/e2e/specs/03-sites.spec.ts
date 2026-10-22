// Bastion Shield e2e — (e) per-site protection off/on (keyed to the top-level
// site, so embeds of a disabled site stay filtered elsewhere) and (f) the
// strict-block interstitial for listed malware domains, including "proceed
// anyway" (which allows only the blocked host in that tab).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { Page } from '@playwright/test';
import { RULE_ID } from '../../../src/shared/constants.ts';
import { expect, test } from '../support/fixtures.ts';
import { HOSTS, KNOWN_TRACKERS } from '../support/hosts.ts';
import { describeResults, loadResources, poll, resourcePageHtml } from '../support/pages.ts';
import type { ResSpec } from '../support/pages.ts';
import { pickGenericSelectors, pickStrictHosts, elementHtml } from '../support/pickers.ts';

test.describe('per-site protection', () => {
  test.afterEach(async ({ ext }) => {
    await ext.sendAndApply({ type: 'sites:set', sites: {} }, 3000);
  });

  test('(e) site:set enabled=false lets everything load; enabled=true blocks again', async ({ page, server, ext, dist }) => {
    const specs: ResSpec[] = KNOWN_TRACKERS.map((t) => ({ url: server.url(t.host, t.path), kind: t.kind, label: t.host }));
    const before = await loadResources(page, server, HOSTS.B, specs, { title: 'protected' });
    const blockedBefore = before.filter((r) => r.blocked).length;
    expect(blockedBefore, `trackers blocked while protection is on\n${describeResults(before)}`).toBeGreaterThan(0);

    const off = await ext.sendAndApply<{ error?: string }>({ type: 'site:set', site: HOSTS.B, patch: { enabled: false } });
    expect(off.response?.error, 'site:set response').toBeUndefined();
    const snap = await ext.snapshot();
    const disabledRule = (snap.dynamicRules as { id: number; condition: { requestDomains?: string[] } }[]).find((r) => r.id === RULE_ID.SITES_DISABLED);
    expect(disabledRule?.condition.requestDomains ?? [], 'dynamic allowAllRequests rule lists the site').toContain(HOSTS.B);

    // Cosmetic filtering must stop too (content script excluded for the site).
    const generic = pickGenericSelectors(dist, 1)[0];
    const extra = generic ? elementHtml(generic.element, 'generic') : '';
    const offRes = await loadResources(page, server, HOSTS.B, specs, { title: 'protection off' });
    const offMsg = describeResults(offRes);
    console.log('[site off]\n' + offMsg);
    for (const r of offRes) expect.soft(r.loaded, `protection off: ${r.label} loads\n${offMsg}`).toBe(true);
    if (generic) {
      server.setPage(HOSTS.B, '/e2e/cosmetic-off.html', `<!doctype html><meta charset="utf-8"><title>off</title>${extra}`);
      await page.goto(server.url(HOSTS.B, '/e2e/cosmetic-off.html'));
      await page.waitForTimeout(800);
      const display = await page.locator('[data-bx-probe="generic"]').evaluate((e) => getComputedStyle(e).display);
      expect.soft(display, `generic selector ${generic.selector} not applied while protection is off`).not.toBe('none');
    }

    await ext.sendAndApply({ type: 'site:set', site: HOSTS.B, patch: { enabled: true } });
    const onRes = await loadResources(page, server, HOSTS.B, specs, { title: 'protection on again' });
    expect(onRes.filter((r) => r.blocked).length, `blocked again after re-enable\n${describeResults(onRes)}`).toBe(blockedBefore);
  });

  test('(e) protection off follows the top-level site: embeds of a disabled site stay filtered elsewhere (BS-3)', async ({ page, server, ext }) => {
    const trackers = KNOWN_TRACKERS.filter((t) => t.kind !== 'fetch');
    const off = await ext.sendAndApply<{ error?: string }>({ type: 'site:set', site: HOSTS.C, patch: { enabled: false } });
    expect(off.response?.error, 'site:set response').toBeUndefined();
    const snap = await ext.snapshot();
    const rule = (snap.dynamicRules as { id: number; condition: { requestDomains?: string[]; resourceTypes?: string[] } }[]).find((r) => r.id === RULE_ID.SITES_DISABLED);
    expect(rule?.condition.requestDomains ?? [], 'protection-off rule lists the site').toContain(HOSTS.C);
    expect.soft(rule?.condition.resourceTypes, 'protection-off rule applies to top-level documents only').toEqual(['main_frame']);

    /** Load `top` with an iframe of `frameHost`; the iframe requests every tracker. Returns tracker hits seen by the server. */
    const loadEmbed = async (topHost: string, frameHost: string, tag: string) => {
      const n = `${tag}-${Date.now().toString(36)}`;
      const frameSpecs: ResSpec[] = trackers.map((t) => ({ url: server.url(t.host, t.path), kind: t.kind, label: t.host }));
      const framePath = `/e2e/embed-${n}.html`;
      server.setPage(frameHost, framePath, resourcePageHtml(frameSpecs, `embed ${frameHost}`));
      const topUrl = server.setPage(topHost, `/e2e/top-${n}.html`, `<!doctype html><meta charset="utf-8"><title>top ${topHost}</title><iframe id="f" src="${server.url(frameHost, framePath)}" width="300" height="100"></iframe>`);
      const t0 = Date.now();
      await page.goto(topUrl, { waitUntil: 'load' });
      const frame = await poll(async () => page.frames().find((f) => f.url().includes(framePath)) ?? null, (f) => f !== null, 5000);
      if (frame) await frame.waitForFunction(() => (window as unknown as { __done?: boolean }).__done === true, null, { timeout: 10_000 }).catch(() => {});
      await page.waitForTimeout(200);
      const framed = server.hits.some((h) => h.t >= t0 && h.host === frameHost && h.pathname === framePath);
      const loaded = trackers.filter((t) => server.hits.some((h) => h.t >= t0 && h.host === t.host && h.pathname === t.path)).map((t) => t.host);
      return { framed, loaded };
    };

    // Enabled site A embeds the disabled site C: C's trackers are blocked inside the iframe.
    const embedded = await loadEmbed(HOSTS.A, HOSTS.C, 'a-embeds-c');
    console.log(`[BS-3] C embedded in A: frame loaded=${embedded.framed}, trackers reaching the server: ${embedded.loaded.join(', ') || 'none'}`);
    expect(embedded.framed, 'the disabled site itself loads as an iframe').toBe(true);
    expect(embedded.loaded, 'trackers inside an embed of a protection-off site are still blocked on an enabled site').toEqual([]);

    // C's own top-level page (and a third-party iframe inside it) is unfiltered.
    const own = await loadEmbed(HOSTS.C, HOSTS.B, 'c-embeds-b');
    console.log(`[BS-3] B embedded in disabled C: trackers reaching the server: ${own.loaded.join(', ') || 'none'}`);
    expect(own.framed, 'third-party iframe loads on the disabled site').toBe(true);
    expect(own.loaded.sort(), 'everything loads inside the frame tree of a protection-off site').toEqual(trackers.map((t) => t.host).sort());
    const top = await loadResources(page, server, HOSTS.C, trackers.map((t) => ({ url: server.url(t.host, t.path), kind: t.kind, label: t.host })), { title: 'disabled site top level' });
    for (const r of top) expect.soft(r.loaded, `protection off: ${r.label} loads on the site itself\n${describeResults(top)}`).toBe(true);
  });
});

const PROCEED = /proceed|anyway|trotzdem|fortfahren|weiter|continuer|quand même|procedi|comunque/i;

async function findProceed(page: Page) {
  const css = page.locator('#bl-proceed, #proceed, [data-action="proceed"]');
  if (await css.count()) return css.first();
  const byRole = page.getByRole('button', { name: PROCEED });
  if (await byRole.count()) return byRole.first();
  const link = page.getByRole('link', { name: PROCEED });
  if (await link.count()) return link.first();
  return null;
}

/** The interstitial may ask for confirmation in a second step (pages/blocked.html does). */
async function confirmIfAsked(page: Page): Promise<boolean> {
  const confirm = page.locator('#bl-confirm-go, [data-action="confirm-proceed"]');
  try {
    await confirm.first().waitFor({ state: 'visible', timeout: 2000 });
  } catch {
    return false;
  }
  await confirm.first().click();
  return true;
}

test.describe('strict block', () => {
  test('(f) navigating to a listed malware domain shows blocked.html; proceed anyway loads the page', async ({ page, server, dist, ext }) => {
    const pick = pickStrictHosts(dist, ['urlhaus', 'ublock-badware'], 1)[0];
    expect(pick, 'a strict-block rule exists in an enabled security list').toBeTruthy();
    const target = server.url(pick.host, '/landing/index.html?campaign=e2e');
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(String(e)));
    page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
    await page.goto(target).catch(() => {});
    await page.waitForURL(/\/pages\/blocked\.html/, { timeout: 10_000 }).catch(() => {});
    const blockedUrl = page.url();
    expect(blockedUrl, `main_frame to ${pick.host} (${pick.rulesetId}#${pick.ruleId}) redirected to the interstitial`).toMatch(/^chrome-extension:\/\/[^/]+\/pages\/blocked\.html/);
    expect(server.hitsFor(pick.host).length, 'the blocked site was never contacted').toBe(0);

    // Reason and list sit behind the «Details» disclosure (phase 2 redesign).
    const details = page.locator('#bl-details-toggle');
    if (await details.count()) await details.click().catch(() => {});
    const body = await poll(() => page.locator('body').innerText().catch(() => ''), (t) => t.includes(pick.host), 5000);
    expect(body, 'interstitial names the blocked host').toContain(pick.host);
    if (pick.listId) {
      const meta = dist.list(pick.listId);
      const names = meta ? Object.values(meta.name).filter(Boolean) : [];
      expect.soft(names.some((n) => body.includes(n as string)) || body.includes(pick.listId), `interstitial names the list (${names.join(' / ')})`).toBe(true);
    }

    const proceed = await findProceed(page);
    expect(proceed, 'a "proceed anyway" control exists').not.toBeNull();
    await proceed!.click();
    const confirmed = await confirmIfAsked(page);
    console.log(`[strict] ${pick.host} (${pick.rulesetId}#${pick.ruleId}) proceed${confirmed ? ' + confirm' : ''}`);
    await page.waitForURL((u) => u.hostname === pick.host, { timeout: 10_000 }).catch(() => {});
    expect(new URL(page.url()).hostname, 'proceed navigates to the original URL').toBe(pick.host);
    const hit = await server.waitForHit((h) => h.host === pick.host && h.pathname === '/landing/index.html', 5000);
    expect(hit, 'the original page was fetched after proceeding').not.toBeNull();
    expect.soft(hit?.query ?? '', 'original query string preserved').toContain('campaign=e2e');

    const session = await ext.api(() => chrome.declarativeNetRequest.getSessionRules());
    const allow = session.find((r) => r.priority === 900 && (r.condition.requestDomains ?? []).some((d) => pick.host === d || pick.host.endsWith('.' + d)));
    expect.soft(allow, 'proceed-anyway session allow rule (priority 900) exists').toBeTruthy();
    expect.soft(errors, 'no console errors on the interstitial').toEqual([]);
  });

  test('(f) proceed anyway allows only the blocked host: third-party trackers on that page stay blocked', async ({ page, server, dist, ext }) => {
    const picks = pickStrictHosts(dist, ['urlhaus', 'ublock-badware'], 3);
    const pick = picks[1] ?? picks[0];
    expect(pick, 'a strict-block rule exists in an enabled security list').toBeTruthy();
    const trackers = KNOWN_TRACKERS.filter((t) => t.kind !== 'fetch').slice(0, 3);
    const specs: ResSpec[] = [
      { url: server.url(pick.host, '/assets/app.js'), kind: 'script', label: 'proceeded host: script' },
      { url: server.url(pick.host, '/assets/logo.gif'), kind: 'img', label: 'proceeded host: image' },
      ...trackers.map((t) => ({ url: server.url(t.host, t.path), kind: t.kind, label: `third-party tracker ${t.host}` })),
    ];
    const landing = `/landing/narrow-${Date.now().toString(36)}.html`;
    server.setPage(pick.host, landing, resourcePageHtml(specs, 'proceeded page'));
    await page.goto(server.url(pick.host, landing)).catch(() => {});
    await page.waitForURL(/\/pages\/blocked\.html/, { timeout: 10_000 }).catch(() => {});
    expect(page.url(), `navigation to ${pick.host} is strict-blocked`).toMatch(/\/pages\/blocked\.html/);
    const proceed = await findProceed(page);
    expect(proceed, 'a "proceed anyway" control exists').not.toBeNull();
    const t0 = Date.now();
    await proceed!.click();
    await confirmIfAsked(page);
    await page.waitForURL((u) => u.hostname === pick.host, { timeout: 10_000 }).catch(() => {});
    expect(new URL(page.url()).hostname, 'proceed navigates to the blocked host').toBe(pick.host);
    await page.waitForFunction(() => (window as unknown as { __done?: boolean }).__done === true, null, { timeout: 10_000 }).catch(() => {});
    await page.waitForTimeout(200);
    const reached = (u: string) => {
      const x = new URL(u);
      return server.hits.some((h) => h.t >= t0 && h.host === x.hostname && h.path === x.pathname + x.search);
    };
    const report = specs.map((s) => `${reached(s.url) ? 'LOADED ' : 'BLOCKED'} ${s.label} ${s.url}`).join('\n');
    console.log(`[proceed narrow] ${pick.host} (${pick.rulesetId}#${pick.ruleId})\n${report}`);
    expect(reached(server.url(pick.host, landing)), 'the proceeded page itself loads').toBe(true);
    for (const s of specs.slice(0, 2)) expect.soft(reached(s.url), `${s.label} loads after proceeding\n${report}`).toBe(true);
    for (const s of specs.slice(2)) expect.soft(reached(s.url), `${s.label} stays blocked after proceeding\n${report}`).toBe(false);

    const tabId = await ext.tabIdOf(page);
    const session = (await ext.api(() => chrome.declarativeNetRequest.getSessionRules())) as { id: number; priority?: number; action: { type: string }; condition: { requestDomains?: string[]; tabIds?: number[] } }[];
    const allow = session.find((r) => r.id >= RULE_ID.SESSION_PROCEED_START && r.id <= RULE_ID.SESSION_PROCEED_END && (r.condition.requestDomains ?? []).includes(pick.host));
    expect.soft(allow?.action.type, 'proceed rule is a plain allow, not allowAllRequests').toBe('allow');
    expect.soft(allow?.condition.tabIds, 'proceed rule is limited to the tab').toEqual([tabId]);
  });
});
