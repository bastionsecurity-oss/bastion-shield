// Bastion Shield e2e — (l) live activity log (port protocol, popup:state and
// the popup feed) and (m) dashboard smoke test: every section renders without
// console errors.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ConsoleMessage, Page } from '@playwright/test';
import { PORT_LIVE } from '../../../src/shared/constants.ts';
import type { ActivityEvent, LivePortMessage, PopupState } from '../../../src/shared/types.ts';
import { expect, test } from '../support/fixtures.ts';
import { HOSTS, KNOWN_TRACKERS } from '../support/hosts.ts';
import { loadResources, poll } from '../support/pages.ts';

function collectErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push('pageerror: ' + String(e?.stack || e)));
  page.on('console', (m: ConsoleMessage) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()} @ ${m.location().url}:${m.location().lineNumber}`);
  });
  page.on('requestfailed', (r) => {
    // Missing packaged files (fonts, icons, locales) show up here.
    if (r.url().startsWith('chrome-extension://')) errors.push(`requestfailed: ${r.url()} ${r.failure()?.errorText}`);
  });
  return errors;
}

/** The popup asks tabs.query({active, currentWindow}); in a test tab that is the popup itself. */
async function pinPopupTab(popup: Page, tabId: number): Promise<void> {
  await popup.addInitScript((id: number) => {
    try {
      const tabs = chrome.tabs as unknown as { query: (q: chrome.tabs.QueryInfo, cb?: (t: chrome.tabs.Tab[]) => void) => unknown };
      const orig = tabs.query.bind(chrome.tabs);
      tabs.query = (q: chrome.tabs.QueryInfo, cb?: (t: chrome.tabs.Tab[]) => void) => {
        if (q && q.active && (q.currentWindow || q.lastFocusedWindow)) {
          const p = chrome.tabs.get(id).then((t) => [t]);
          if (cb) {
            void p.then(cb);
            return undefined;
          }
          return p;
        }
        return orig(q, cb as never);
      };
    } catch {
      /* not an extension page */
    }
  }, tabId);
}

test.describe('live log', () => {
  test('(l) blocked requests reach the live port, popup:state and the popup feed', async ({ page, server, ext, dist }) => {
    // Subscribe before the page loads so we see the stream, not just the backlog.
    const helper = await ext.helper();
    await helper.evaluate((name: string) => {
      const w = window as unknown as { __live: unknown[]; __livePort?: chrome.runtime.Port };
      w.__live = [];
      w.__livePort?.disconnect();
      const port = chrome.runtime.connect({ name });
      port.onMessage.addListener((m) => w.__live.push(m));
      port.postMessage({ subscribe: 'all' });
      w.__livePort = port;
    }, PORT_LIVE);

    const specs = KNOWN_TRACKERS.map((t) => ({ url: server.url(t.host, t.path), kind: t.kind, label: t.host }));
    const rs = await loadResources(page, server, HOSTS.A, specs, { title: 'live log' });
    const blockedHosts = rs.filter((r) => r.blocked).map((r) => new URL(r.url).hostname);
    expect(blockedHosts.length, 'some requests were blocked').toBeGreaterThan(0);
    const tabId = await ext.tabIdOf(page);
    expect(tabId, 'tab id of the fixture page').toBeGreaterThan(0);

    const live = await poll(
      () => helper.evaluate(() => (window as unknown as { __live: LivePortMessage[] }).__live),
      (msgs) => msgs.some((m) => m.type === 'event' && m.event.tabId === tabId && m.event.kind === 'blocked'),
      8000,
      200,
    );
    const events = live.flatMap((m) => (m.type === 'event' ? [m.event] : m.type === 'backlog' ? m.events : [])) as ActivityEvent[];
    const mine = events.filter((e) => e.tabId === tabId);
    expect(mine.length, `live events for tab ${tabId} (got ${live.length} port messages)`).toBeGreaterThan(0);
    for (const e of mine) {
      expect.soft(typeof e.t === 'number' && typeof e.url === 'string' && typeof e.host === 'string', `well-formed event ${JSON.stringify(e)}`).toBe(true);
    }
    const loggedHosts = new Set(mine.map((e) => e.host));
    for (const h of blockedHosts) expect.soft(loggedHosts.has(h), `live event for ${h}`).toBe(true);
    expect.soft(mine.every((e) => e.site === HOSTS.A), 'events carry the page site key').toBe(true);
    expect.soft(mine.filter((e) => KNOWN_TRACKERS.some((t) => t.host === e.host)).every((e) => e.thirdParty), 'tracker events marked third-party').toBe(true);

    const state = await ext.send<PopupState & { error?: string }>({ type: 'popup:state', tabId });
    expect(state?.error, 'popup:state response').toBeUndefined();
    expect.soft(state.host, 'popup:state host').toBe(HOSTS.A);
    expect.soft(state.filterable, 'popup:state filterable').toBe(true);
    expect.soft(state.counts.blocked + state.counts.redirected, 'popup:state counts').toBeGreaterThanOrEqual(blockedHosts.length);
    expect.soft(state.recent.length, 'popup:state recent events').toBeGreaterThan(0);

    // The real popup UI, pinned to the fixture tab.
    const popup = await ext.context.newPage();
    const errors = collectErrors(popup);
    await pinPopupTab(popup, tabId);
    const popupPath = (dist.manifest.action?.default_popup ?? 'ui/popup.html').replace(/^\//, '');
    await popup.goto(`${ext.origin}/${popupPath}`);
    await expect(popup.locator('#pp-host')).toContainText(HOSTS.A, { timeout: 5000 });
    const count = await poll(() => popup.locator('#pp-count').innerText().catch(() => '0'), (t) => Number(t.replace(/\D/g, '')) > 0, 5000);
    const before = Number(count.replace(/\D/g, ''));
    expect.soft(before, 'popup counter').toBeGreaterThan(0);
    // The data estimate follows the blocked requests (never 0 kB once something was blocked).
    expect.soft(await popup.locator('#pp-data').innerText(), 'data saved estimate').not.toBe('0');
    // A new block while the popup is open must be counted without reopening it.
    await page.evaluate((u: string) => {
      const i = new Image();
      i.src = u;
      document.body.appendChild(i);
    }, server.url('ad.doubleclick.net', '/ddm/live-' + Date.now() + '.gif'));
    const after = await poll(() => popup.locator('#pp-count').innerText().then((t) => Number(t.replace(/\D/g, ''))), (n) => n > before, 6000, 200);
    expect.soft(after, 'popup counter updates live').toBeGreaterThan(before);
    expect.soft(errors, 'popup console errors').toEqual([]);
    await popup.close();
  });
});

test.describe('popup ?tabId=', () => {
  test('(l) popup.html?tabId=<n> shows that tab without chrome.tabs.query', async ({ page, server, ext, dist }) => {
    const specs = KNOWN_TRACKERS.slice(0, 3).map((t) => ({ url: server.url(t.host, t.path), kind: t.kind, label: t.host }));
    const rs = await loadResources(page, server, HOSTS.B, specs, { title: 'popup tabId' });
    expect(rs.some((r) => r.blocked), 'something was blocked on the fixture page').toBe(true);
    const tabId = await ext.tabIdOf(page);
    expect(tabId, 'tab id of the fixture page').toBeGreaterThan(0);
    const popup = await ext.context.newPage();
    const errors = collectErrors(popup);
    // No pinPopupTab(): the query parameter alone must select the tab (the
    // popup's own tab is an extension page and would show "not filterable").
    const popupPath = (dist.manifest.action?.default_popup ?? 'ui/popup.html').replace(/^\//, '');
    await popup.goto(`${ext.origin}/${popupPath}?tabId=${tabId}`);
    await expect(popup.locator('#pp-host')).toContainText(HOSTS.B, { timeout: 5000 });
    await expect(popup.locator('#pp-unfilterable')).toBeHidden();
    const count = await poll(() => popup.locator('#pp-count').innerText().catch(() => '0'), (t) => Number(t.replace(/\D/g, '')) > 0, 5000);
    expect.soft(Number(count.replace(/\D/g, '')), 'popup counter for the selected tab').toBeGreaterThan(0);
    expect.soft(errors, 'popup console errors').toEqual([]);
    await popup.close();
  });
});

test.describe('dashboard', () => {
  test('(m) every dashboard section renders without console errors', async ({ ext, dist }, testInfo) => {
    const page = await ext.context.newPage();
    const errors = collectErrors(page);
    const optionsPage = (dist.manifest.options_page as string | undefined) ?? 'ui/dashboard.html';
    await page.goto(`${ext.origin}/${optionsPage.replace(/^\//, '')}`, { waitUntil: 'load' });
    await page.waitForTimeout(800);
    const bodyText = await page.locator('body').innerText();
    expect(bodyText.trim().length, 'dashboard renders text').toBeGreaterThan(20);

    // Discover navigation generically so the test survives UI restructuring:
    // in-page links and tabs inside <nav>, one per distinct target.
    const navs = page.locator('nav a[href^="#"], nav [role="tab"], nav button[data-view], nav a[data-view]');
    const n = await navs.count();
    const visited: { label: string; hash: string; textLength: number; newErrors: string[] }[] = [];
    const seenTargets = new Set<string>();
    for (let i = 0; i < n; i++) {
      const el = navs.nth(i);
      if (!(await el.isVisible().catch(() => false))) continue;
      const target = (await el.getAttribute('href')) || (await el.getAttribute('data-view')) || (await el.getAttribute('aria-controls')) || `#${i}`;
      if (seenTargets.has(target)) continue;
      seenTargets.add(target);
      const label = ((await el.innerText().catch(() => '')) || (await el.getAttribute('aria-label')) || target).replace(/\s+/g, ' ').trim().slice(0, 40);
      const errBefore = errors.length;
      await el.click({ timeout: 3000 }).catch((e) => errors.push(`click ${label}: ${String(e).split('\n')[0]}`));
      await page.waitForTimeout(400);
      const main = page.locator('main, [role="main"]').first();
      const text = (await main.count()) ? await main.innerText().catch(() => '') : await page.locator('body').innerText();
      visited.push({ label, hash: new URL(page.url()).hash, textLength: text.trim().length, newErrors: errors.slice(errBefore) });
      expect.soft(text.trim().length, `section "${label}" renders content`).toBeGreaterThan(10);
    }
    await testInfo.attach('dashboard-sections', { body: JSON.stringify(visited, null, 2), contentType: 'application/json' });
    console.log(`[dashboard] sections visited: ${visited.map((v) => v.label + (v.hash ? ' ' + v.hash : '')).join(' | ')}`);
    expect.soft(visited.length, 'navigation entries found').toBeGreaterThan(1);
    expect(errors, 'dashboard console errors').toEqual([]);
    await page.close();
  });
});
