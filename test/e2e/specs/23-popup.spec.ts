// Bastion Shield e2e — toolbar popup «UI Optimised» (Phase 3, P01–P15).
// Every control of the compact popup does what its label says: protection
// switch, blocking mode, reload bar (never covers the CTA), «Melden…» bottom
// sheet (focus trap, starts on «Abbrechen», Escape, focus back, «Was geteilt
// wird», GitHub, e-mail, GitHub error + «Erneut öffnen»), settings / expand,
// «Cyber-Vorfall?» URL, counter off + «Einschalten», the calm states («Hier
// nicht aktiv», «Schutz pausiert», «Keine Verbindung» + «Erneut versuchen»
// with its loading state), keyboard-only order, light and dark, long hosts
// and 1'000+ counts without overflow, no raw i18n keys, no failed
// chrome-extension:// requests.
//
// States the fixture cannot produce (service worker unreachable, browser page,
// policy kill switch, long host) are simulated in the popup page itself: an
// init script wraps chrome.runtime.sendMessage for popup:state only.
// PP_SHOTS=<dir> saves light/dark screenshots of P01, P03, P04, P07, P08, P09.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import fs from 'node:fs';
import path from 'node:path';
import type { ConsoleMessage, Page } from '@playwright/test';
import { expect, test } from '../support/fixtures.ts';
import { HOSTS, KNOWN_TRACKERS } from '../support/hosts.ts';
import { loadResources, poll } from '../support/pages.ts';

const INCIDENT = /^https:\/\/www\.bastionsecurity\.ch\/(kontakt|en\/contact)#vorfall$/;
const SHOTS = process.env.PP_SHOTS ?? '';
const LONG_HOST = 'portal.kundenservice-verwaltung.beispiel-versicherung.ch';

type Scheme = 'light' | 'dark';

interface Mock {
  /** popup:state answers with an error this many times. */
  failState?: number;
  /** Delay before popup:state answers (ms). */
  delay?: number;
  /** Deep-merged into every popup:state reply. */
  patch?: Record<string, unknown>;
  /** chrome.tabs.create rejects (GitHub cannot be opened). */
  failTabsCreate?: boolean;
}

interface Ext {
  context: import('@playwright/test').BrowserContext;
  origin: string;
}

function collectErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push('pageerror: ' + String(e?.stack || e)));
  page.on('console', (m: ConsoleMessage) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()} @ ${m.location().url}:${m.location().lineNumber}`);
  });
  page.on('requestfailed', (r) => {
    if (r.url().startsWith('chrome-extension://')) errors.push(`requestfailed: ${r.url()} ${r.failure()?.errorText}`);
  });
  return errors;
}

async function openPopup(ext: Ext, tabId: number, mock: Mock = {}, scheme: Scheme = 'light', height = 640): Promise<{ popup: Page; errors: string[] }> {
  const popup = await ext.context.newPage();
  const errors = collectErrors(popup);
  await popup.setViewportSize({ width: 360, height });
  await popup.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
  await popup.addInitScript((m: Mock) => {
    const w = window as unknown as Record<string, unknown> & { __ppMock: Mock; __closed: number; __created: string[]; __mailto: string[]; __stateCalls: number };
    w.__closed = 0;
    w.__created = [];
    w.__mailto = [];
    w.__stateCalls = 0;
    w.__ppMock = m;
    window.close = () => {
      w.__closed++;
    };
    const merge = (a: Record<string, unknown>, b: Record<string, unknown>): Record<string, unknown> => {
      for (const [k, v] of Object.entries(b)) {
        const cur = a[k];
        if (v && typeof v === 'object' && !Array.isArray(v) && cur && typeof cur === 'object' && !Array.isArray(cur)) merge(cur as Record<string, unknown>, v as Record<string, unknown>);
        else a[k] = v;
      }
      return a;
    };
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
    const rt = chrome.runtime as unknown as { sendMessage: (msg: { type?: string }) => Promise<unknown> };
    const orig = rt.sendMessage.bind(chrome.runtime);
    rt.sendMessage = async (msg: { type?: string }) => {
      if (msg?.type === 'popup:state') {
        w.__stateCalls++;
        const mm = w.__ppMock;
        if (mm.delay) await sleep(mm.delay);
        if ((mm.failState ?? 0) > 0) {
          mm.failState!--;
          return { error: 'mock: no connection' };
        }
        const r = await orig(msg);
        return mm.patch && r && typeof r === 'object' ? merge(r as Record<string, unknown>, structuredClone(mm.patch)) : r;
      }
      return orig(msg);
    };
    const tabs = chrome.tabs as unknown as { create: (p: { url?: string }) => Promise<unknown> };
    tabs.create = async (p: { url?: string }) => {
      w.__created.push(p.url ?? '');
      if (w.__ppMock.failTabsCreate) throw new Error('mock: offline');
      return { id: -1 };
    };
    // mailto: drafts are recorded, not handed to the OS.
    document.addEventListener(
      'click',
      (e) => {
        const a = (e.target as Element | null)?.closest?.('a[href^="mailto:"]') as HTMLAnchorElement | null;
        if (a) {
          w.__mailto.push(a.href);
          e.preventDefault();
        }
      },
      true,
    );
  }, mock);
  await popup.goto(`${ext.origin}/ui/popup.html?tabId=${tabId}`);
  return { popup, errors };
}

/** Screenshot for the hand-over. Like the real popup, the window is as tall as the content (sheets: 640). */
async function shot(popup: Page, name: string, scheme: Scheme): Promise<void> {
  if (!SHOTS) return;
  fs.mkdirSync(SHOTS, { recursive: true });
  const sheet = (await popup.locator('dialog[open]').count()) > 0;
  const before = popup.viewportSize();
  if (!sheet) {
    const h = await popup.evaluate(() => Math.ceil(document.body.getBoundingClientRect().height));
    await popup.setViewportSize({ width: 360, height: h });
  }
  await popup.waitForTimeout(150);
  await popup.screenshot({ path: path.join(SHOTS, `${name}-${scheme}.png`) });
  if (before && !sheet) await popup.setViewportSize(before);
}

/** No raw message keys or __MSG_ placeholders anywhere in the visible text. */
async function expectNoRawKeys(popup: Page): Promise<void> {
  const text = await popup.locator('body').innerText();
  expect.soft(text, 'no __MSG_ placeholders').not.toMatch(/__MSG_/);
  expect.soft(text, 'no raw i18n keys').not.toMatch(/\b(popup|report|nerd|action|mode|cta)[A-Z][A-Za-z]+\b/);
  expect.soft(text, 'no middle dot separators').not.toMatch(/ · /);
}

/** Nothing overflows the 360px popup and no tile content spills out of its tile. */
async function expectNoOverflow(popup: Page): Promise<void> {
  const res = await popup.evaluate(() => {
    const out: string[] = [];
    if (document.documentElement.scrollWidth > 360) out.push(`page scrollWidth ${document.documentElement.scrollWidth}`);
    for (const tile of Array.from(document.querySelectorAll<HTMLElement>('.pp-mod, .pp-actions, .pp-org'))) {
      if (tile.hidden || tile.offsetParent === null) continue;
      const r = tile.getBoundingClientRect();
      for (const el of Array.from(tile.querySelectorAll<HTMLElement>('*'))) {
        if (el.offsetParent === null || el.closest('.sr-only')) continue;
        const c = el.getBoundingClientRect();
        if (c.width === 0) continue;
        if (c.right > r.right + 0.5 || c.left < r.left - 0.5) out.push(`${el.id || el.className} spills out of ${tile.id || tile.className}`);
      }
    }
    return out;
  });
  expect.soft(res, 'no horizontal overflow').toEqual([]);
}

async function trackerTab(page: Page, server: import('../support/server.ts').FixtureServer, ext: { tabIdOf(p: Page): Promise<number> }, host: string, n = 4): Promise<number> {
  const specs = KNOWN_TRACKERS.slice(0, n).map((t) => ({ url: server.url(t.host, t.path), kind: t.kind, label: t.host }));
  await loadResources(page, server, host, specs, { title: 'popup phase 3' });
  const tabId = await ext.tabIdOf(page);
  expect(tabId).toBeGreaterThan(0);
  return tabId;
}

test.describe('popup (UI Optimised)', () => {
  test.beforeAll(async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { ui: { incidentCta: true, language: 'de', activityLog: true, badge: true } } }, 3000);
  });

  for (const scheme of ['light', 'dark'] as const) {
    test(`standard, controls and reload bar (${scheme})`, async ({ page, server, ext }) => {
      const tabId = await trackerTab(page, server, ext, HOSTS.C);
      const { popup, errors } = await openPopup(ext, tabId, {}, scheme);
      await expect(popup.locator('#pp-host')).toContainText(HOSTS.C);
      await expect(popup.locator('#pp-host')).toHaveAttribute('title', HOSTS.C);
      await expect(popup.locator('#pp-host')).toHaveAttribute('translate', 'no');
      await expect(popup.locator('#pp-toggle-state')).toHaveText('Schutz ein');
      await poll(() => popup.locator('#pp-count').innerText(), (t) => Number(t.replace(/\D/g, '')) > 0, 5000);
      await expect(popup.locator('#pp-legend-blocked-text')).toContainText('blockiert');
      await expect(popup.locator('#pp-report')).toHaveAttribute('aria-label', 'Defekte Seite melden…');

      // Tokens: ground, tile, protection tile per scheme (P01 / P13).
      const colors = await popup.evaluate(() => {
        // Computed colours may come back as color(srgb …) (color-mix): normalise through a canvas.
        const ctx = document.createElement('canvas').getContext('2d')!;
        const rgb = (sel: string): string => {
          ctx.clearRect(0, 0, 1, 1);
          ctx.fillStyle = getComputedStyle(document.querySelector(sel)!).backgroundColor;
          ctx.fillRect(0, 0, 1, 1);
          const [r, g, b] = ctx.getImageData(0, 0, 1, 1).data;
          return `rgb(${r}, ${g}, ${b})`;
        };
        return { ground: rgb('body'), tile: rgb('#pp-count-section'), protect: rgb('#pp-protect'), cta: rgb('#pp-cta-slot a') };
      });
      if (scheme === 'light') {
        expect.soft(colors).toEqual({ ground: 'rgb(242, 244, 245)', tile: 'rgb(255, 255, 255)', protect: 'rgb(23, 28, 30)', cta: 'rgb(218, 41, 28)' });
      } else {
        // #252A2C comes from color-mix (6 % white on #171C1E): the blue channel may round to 43.
        expect.soft({ ...colors, tile: colors.tile.replace('43)', '44)') }).toEqual({ ground: 'rgb(19, 18, 21)', tile: 'rgb(37, 42, 44)', protect: 'rgb(215, 221, 223)', cta: 'rgb(218, 41, 28)' });
      }
      // 44px controls, 52px round actions, radius 24 tiles.
      const sizes = await popup.evaluate(() => ({
        seg: Math.round(document.querySelector<HTMLElement>('#pp-mode-slot [data-value="standard"]')!.getBoundingClientRect().height),
        round: Math.round(document.querySelector<HTMLElement>('#pp-expand')!.getBoundingClientRect().height),
        radius: getComputedStyle(document.querySelector('#pp-count-section')!).borderTopLeftRadius,
        width: document.body.getBoundingClientRect().width,
      }));
      expect.soft(sizes).toEqual({ seg: 44, round: 52, radius: '24px', width: 360 });
      await shot(popup, 'P01', scheme);
      await expectNoRawKeys(popup);
      await expectNoOverflow(popup);

      // ---- Protection switch (P02): off shows the note, on again ---------------
      const protect = popup.locator('#pp-protect');
      await protect.click();
      await expect(protect).toHaveAttribute('aria-checked', 'false');
      await expect(popup.locator('#pp-toggle-state')).toHaveText('Schutz aus');
      await expect(popup.locator('#pp-site-off')).toBeVisible();
      await expect(popup.locator('#pp-count-section')).toBeHidden();
      const sitesOff = await ext.send<{ sites?: Record<string, { enabled?: boolean }> }>({ type: 'sites:get' });
      expect.soft(Object.values(sitesOff?.sites ?? {}).some((s) => s?.enabled === false), 'site saved as off').toBe(true);
      await expect(popup.locator('#pp-reload')).toBeVisible();
      await protect.click();
      await expect(protect).toHaveAttribute('aria-checked', 'true');
      // Back to how the page was loaded: no reload needed.
      await expect(popup.locator('#pp-reload')).toBeHidden();

      // ---- Mode + reload bar (P04) ---------------------------------------------
      const strict = popup.locator('#pp-mode-slot [data-value="aggressive"]');
      await strict.click();
      await expect(strict).toHaveAttribute('aria-checked', 'true');
      const bar = popup.locator('#pp-reload');
      await expect(bar).toBeVisible();
      await expect(bar).toContainText('Gilt nach dem Neuladen');
      const geo = await popup.evaluate(() => ({
        bar: document.getElementById('pp-reload')!.getBoundingClientRect().top,
        cta: document.getElementById('pp-cta-slot')!.getBoundingClientRect().bottom,
        page: document.documentElement.scrollHeight,
        barBottom: document.getElementById('pp-reload')!.getBoundingClientRect().bottom,
      }));
      expect.soft(geo.bar, 'reload bar sits below the CTA').toBeGreaterThanOrEqual(geo.cta);
      await shot(popup, 'P04', scheme);
      await popup.locator('#pp-mode-slot [data-value="standard"]').click();
      await expect(bar).toBeHidden();
      await strict.click();
      await expect(bar).toBeVisible();
      // «Neu laden» reloads the tab and closes the popup.
      const reloaded = page.waitForEvent('load');
      await popup.locator('#pp-reload-btn').click();
      await reloaded;
      expect(await poll(() => popup.evaluate(() => (window as unknown as { __closed: number }).__closed), (n) => n > 0, 3000, 50)).toBeGreaterThan(0);
      await ext.send({ type: 'site:set', site: HOSTS.C, patch: { mode: 'standard' } });

      // ---- «Cyber-Vorfall?» -----------------------------------------------------
      const cta = popup.locator('#pp-cta-slot a[data-cta="incident"]');
      await expect(cta).toHaveAttribute('href', INCIDENT);
      await expect(cta).toHaveAttribute('target', '_blank');

      expect(errors, 'console errors / failed extension requests').toEqual([]);
      await popup.close();
    });
  }

  test('keyboard only: focus order, switch, mode, sheet and focus return (P14)', async ({ page, server, ext }) => {
    const tabId = await trackerTab(page, server, ext, HOSTS.B);
    const { popup, errors } = await openPopup(ext, tabId);
    await expect(popup.locator('#pp-host')).toContainText(HOSTS.B);
    await expect(popup.locator('#pp-report')).toBeVisible();

    const focused = () => popup.evaluate(() => {
      const a = document.activeElement as HTMLElement | null;
      return a ? a.id || a.getAttribute('data-value') || a.getAttribute('data-cta') || a.getAttribute('data-dialog') || a.tagName : '';
    });
    const order: string[] = [];
    for (let i = 0; i < 5; i++) {
      await popup.keyboard.press('Tab');
      order.push(await focused());
    }
    expect(order).toEqual(['pp-protect', 'standard', 'pp-report', 'pp-expand', 'incident']);
    // Focus ring: 2px, visible.
    const ring = await popup.evaluate(() => getComputedStyle(document.activeElement!).outlineWidth);
    expect.soft(ring).toBe('2px');

    // Space toggles protection; arrows change the mode.
    await popup.locator('#pp-protect').focus();
    await popup.keyboard.press('Space');
    await expect(popup.locator('#pp-protect')).toHaveAttribute('aria-checked', 'false');
    await popup.keyboard.press('Space');
    await expect(popup.locator('#pp-protect')).toHaveAttribute('aria-checked', 'true');
    await popup.keyboard.press('Tab');
    await popup.keyboard.press('ArrowRight');
    await expect(popup.locator('#pp-mode-slot [data-value="aggressive"]')).toHaveAttribute('aria-checked', 'true');
    await popup.keyboard.press('ArrowLeft');
    await expect(popup.locator('#pp-mode-slot [data-value="standard"]')).toHaveAttribute('aria-checked', 'true');

    // Enter on «Melden…» opens the sheet on «Abbrechen»; Tab stays inside; Escape closes; focus returns.
    await popup.locator('#pp-report').focus();
    await popup.keyboard.press('Enter');
    const sheet = popup.locator('dialog.pp-sheet');
    await expect(sheet).toBeVisible();
    expect(await focused()).toBe('cancel');
    const inside: boolean[] = [];
    for (let i = 0; i < 6; i++) {
      await popup.keyboard.press('Tab');
      inside.push(await popup.evaluate(() => !!document.activeElement?.closest('dialog.pp-sheet')));
    }
    expect(inside.every(Boolean), 'focus trapped in the sheet').toBe(true);
    await popup.keyboard.press('Shift+Tab');
    expect(await popup.evaluate(() => !!document.activeElement?.closest('dialog.pp-sheet'))).toBe(true);
    await popup.keyboard.press('Escape');
    await expect(sheet).toHaveCount(0);
    expect(await focused()).toBe('pp-report');
    expect(await popup.evaluate(() => (window as unknown as { __closed: number }).__closed), 'Escape closes only the sheet').toBe(0);

    expect(errors).toEqual([]);
    await popup.close();
  });

  for (const scheme of ['light', 'dark'] as const) {
    test(`report sheet: what is shared, GitHub, close paths (P08, P09) (${scheme})`, async ({ page, server, ext }) => {
      const tabId = await trackerTab(page, server, ext, HOSTS.A);
      const { popup, errors } = await openPopup(ext, tabId, {}, scheme);
      await expect(popup.locator('#pp-report')).toBeVisible();
      await popup.locator('#pp-report').click();
      const sheet = popup.locator('dialog.pp-sheet');
      await expect(sheet).toBeVisible();
      await expect(sheet.locator('.pp-sheet__title')).toHaveText(`${HOSTS.A} melden`);
      await expect(sheet.locator('.pp-sheet__title [translate="no"]')).toHaveText(HOSTS.A);
      await expect(sheet).toContainText('Öffnet ein öffentliches GitHub-Issue. Sie senden es selbst.');
      await expect(sheet.locator('[data-dialog="confirm"]')).toHaveText('Auf GitHub öffnen');
      await expect(sheet).toHaveCSS('overscroll-behavior-y', 'contain');
      // The sheet sits at the bottom, 8px from the edges, on a scrim.
      const box = await sheet.boundingBox();
      expect.soft(Math.round(box!.x)).toBe(8);
      expect.soft(Math.round(box!.width)).toBe(344);
      await shot(popup, 'P08', scheme);

      // «Was geteilt wird» disclosure.
      const toggle = sheet.locator('[data-share="toggle"]');
      await expect(toggle).toHaveAttribute('aria-expanded', 'false');
      await expect(sheet.locator('.pp-share__aside')).toHaveText('Ohne Pfad und Verlauf');
      await toggle.click();
      await expect(toggle).toHaveAttribute('aria-expanded', 'true');
      const panel = sheet.locator('.pp-share__panel');
      await expect(panel).toBeVisible();
      await expect(panel.locator('dt')).toHaveText(['Website', 'Version', 'Browser', 'Modus', 'Filterlisten']);
      await expect(panel.locator('dd').first()).toHaveText(HOSTS.A);
      await expect(panel.locator('dd').nth(1)).toContainText('Bastion Shield ');
      await expect(panel.locator('dd').nth(3)).toHaveText('Standard, Schutz ein');
      await expect(panel).toContainText('Nicht geteilt: Pfad, Suche, Verlauf, persönliche Daten.');
      await shot(popup, 'P09', scheme);
      await toggle.click();
      await expect(panel).toBeHidden();

      // Close button and «Abbrechen» close without opening anything; focus back on «Melden…».
      await sheet.locator('[data-dialog="close"]').click();
      await expect(sheet).toHaveCount(0);
      await expect(popup.locator('#pp-report')).toBeFocused();
      await popup.locator('#pp-report').click();
      await popup.locator('dialog.pp-sheet [data-dialog="cancel"]').click();
      await expect(popup.locator('dialog.pp-sheet')).toHaveCount(0);
      expect(await popup.evaluate(() => (window as unknown as { __created: string[] }).__created)).toEqual([]);

      // «Auf GitHub öffnen» opens the prefilled issue (host only, no path) and closes the popup.
      await popup.locator('#pp-report').click();
      await popup.locator('dialog.pp-sheet [data-dialog="confirm"]').click();
      const created = await poll(() => popup.evaluate(() => (window as unknown as { __created: string[] }).__created), (c) => c.length > 0, 3000, 50);
      expect(created[0]).toMatch(/^https:\/\/github\.com\/.+\/issues\/new\?/);
      const q = new URL(created[0]!).searchParams;
      expect.soft(q.get('site')).toBe(HOSTS.A);
      expect.soft(created[0]).not.toContain('/e2e/');
      expect(await poll(() => popup.evaluate(() => (window as unknown as { __closed: number }).__closed), (n) => n > 0, 3000, 50)).toBeGreaterThan(0);

      await expectNoRawKeys(popup);
      expect(errors).toEqual([]);
      await popup.close();
    });
  }

  test('report by e-mail (P10) and GitHub unreachable with retry (P11)', async ({ page, server, ext }) => {
    const tabId = await trackerTab(page, server, ext, HOSTS.A);
    const email = 'it-sicherheit.meldungen@kantonsverwaltung-beispiel.ch';
    const { popup, errors } = await openPopup(ext, tabId, { patch: { managed: { reportBrokenSite: 'email', supportEmail: email } } });
    await popup.locator('#pp-report').click();
    const sheet = popup.locator('dialog.pp-sheet');
    await expect(sheet).toHaveAttribute('data-channel', 'email');
    await expect(sheet).toContainText('Ihr Mailprogramm öffnet einen Entwurf. Senden tun Sie selbst.');
    const to = sheet.locator('.pp-sheet__to-val');
    await expect(to).toHaveText(email);
    await expect(to).toHaveAttribute('title', email);
    expect(await to.evaluate((el) => el.scrollWidth > el.clientWidth), 'long address is cut, not overflowing').toBe(true);
    await shot(popup, 'P10', 'light');
    await sheet.locator('[data-dialog="confirm"]').click();
    await expect(sheet.locator('[data-dialog="confirm"]')).toHaveCount(0);
    const mail = await popup.evaluate(() => (window as unknown as { __mailto: string[] }).__mailto);
    expect(mail[0]).toMatch(new RegExp(`^mailto:${encodeURIComponent(email).replace(/\./g, '\\.')}\\?subject=`));
    expect(decodeURIComponent(mail[0]!)).toContain(`Site: ${HOSTS.A}`);
    expect(await poll(() => popup.evaluate(() => (window as unknown as { __closed: number }).__closed), (n) => n > 0, 3000, 50)).toBeGreaterThan(0);
    await popup.close();

    // P11: GitHub cannot be opened -> inline error, the sheet stays, «Erneut öffnen» tries again.
    const second = await openPopup(ext, tabId, { failTabsCreate: true });
    const p2 = second.popup;
    await p2.locator('#pp-report').click();
    const s2 = p2.locator('dialog.pp-sheet');
    await s2.locator('[data-dialog="confirm"]').click();
    const err = s2.locator('.pp-sheet__error');
    await expect(err).toBeVisible();
    await expect(err).toHaveAttribute('role', 'alert');
    await expect(err).toContainText('GitHub nicht erreichbar');
    await expect(s2.locator('[data-dialog="confirm"]')).toHaveText('Erneut öffnen');
    await shot(p2, 'P11', 'light');
    await p2.evaluate(() => ((window as unknown as { __ppMock: Mock }).__ppMock.failTabsCreate = false));
    await s2.locator('[data-dialog="confirm"]').click();
    await expect(s2).toHaveCount(0);
    const created = await p2.evaluate(() => (window as unknown as { __created: string[] }).__created);
    expect(created.length, 'tried twice').toBe(2);
    expect(errors.concat(second.errors)).toEqual([]);
    await p2.close();
  });

  for (const scheme of ['light', 'dark'] as const) {
    test(`long host, 1'000+ counts and organisation (P03) (${scheme})`, async ({ page, server, ext }) => {
      const tabId = await trackerTab(page, server, ext, HOSTS.A);
      const patch = {
        host: LONG_HOST,
        counts: { blocked: 11903, redirected: 944, stripped: 0, debounced: 0, thirdPartyHosts: 312 },
        recent: [],
        managed: { organizationName: 'Bastion Security GmbH, Abteilung Informatik und Sicherheit' },
      };
      const { popup, errors } = await openPopup(ext, tabId, { patch }, scheme);
      const host = popup.locator('#pp-host');
      await expect(host).toHaveAttribute('title', LONG_HOST);
      await expect(popup.locator('#pp-host-full')).toHaveText(LONG_HOST);
      const vis = await popup.locator('#pp-host-vis').innerText();
      expect(vis, 'cut in the middle').toContain('…');
      expect(vis.startsWith('portal'), 'start stays').toBe(true);
      expect(vis.endsWith('.ch'), 'TLD stays').toBe(true);
      expect(await popup.locator('#pp-host-vis').evaluate((el) => el.scrollWidth <= el.clientWidth), 'host fits its tile').toBe(true);
      await poll(() => popup.locator('#pp-count').innerText(), (t) => Number(t.replace(/\D/g, '')) >= 12847, 5000);
      // Swiss grouping (de-CH): 12’847.
      expect(await popup.locator('#pp-count').innerText()).toMatch(/^1\d[’'][\d]{3}$/);
      await expect(popup.locator('#pp-legend-blocked-text')).toHaveText(/^11[’']\d{3} blockiert$/);
      await expect(popup.locator('#pp-c-third')).toHaveText(/^3\d\d Hosts$/);
      const org = popup.locator('.pp-org__name');
      await expect(org).toBeVisible();
      expect(await org.evaluate((el) => el.scrollWidth > el.clientWidth), 'org name cut at the end').toBe(true);
      await shot(popup, 'P03', scheme);
      await expectNoOverflow(popup);
      await expectNoRawKeys(popup);
      expect(errors).toEqual([]);
      await popup.close();
    });
  }

  for (const scheme of ['light', 'dark'] as const) {
    test(`«Keine Verbindung» and «Erneut versuchen» re-runs the state request (P07) (${scheme})`, async ({ page, server, ext }) => {
      const tabId = await trackerTab(page, server, ext, HOSTS.C);
      const { popup, errors } = await openPopup(ext, tabId, { failState: 1 }, scheme);
      const tile = popup.locator('#pp-error');
      await expect(tile).toBeVisible();
      await expect(tile).toContainText('Keine Verbindung');
      await expect(tile).toContainText('Bastion Shield antwortet gerade nicht.');
      await expect(popup.locator('#pp-top, .pp-top')).toBeHidden();
      await expect(popup.locator('#pp-expand')).toBeVisible();
      await expect(popup.locator('#pp-cta-slot a[data-cta="incident"]')).toBeVisible();
      const retry = popup.locator('#pp-retry');
      await expect(retry).toHaveText('Erneut versuchen');
      expect(await popup.evaluate(() => (window as unknown as { __stateCalls: number }).__stateCalls)).toBe(1);

      // Retry fails again (slow answer): spinner after ~150 ms, label kept, still the error tile.
      await popup.evaluate(() => {
        const m = (window as unknown as { __ppMock: Mock }).__ppMock;
        m.failState = 1;
        m.delay = 700;
      });
      await retry.click();
      await expect(retry).toHaveAttribute('aria-busy', 'true');
      await expect(retry).toHaveText('Erneut versuchen');
      await shot(popup, 'P07', scheme);
      await expect(retry).not.toHaveAttribute('aria-busy', 'true', { timeout: 3000 });
      await expect(tile).toBeVisible();
      expect(await popup.evaluate(() => (window as unknown as { __stateCalls: number }).__stateCalls)).toBe(2);

      // A fast answer: no spinner flash, the popup appears.
      await popup.evaluate(() => {
        (window as unknown as { __ppMock: Mock }).__ppMock.delay = 0;
      });
      await retry.click();
      await expect(tile).toBeHidden();
      await expect(popup.locator('#pp-host')).toContainText(HOSTS.C);
      await expect(popup.locator('#pp-protect')).toBeFocused();
      expect(await popup.evaluate(() => (window as unknown as { __stateCalls: number }).__stateCalls)).toBe(3);
      await expectNoRawKeys(popup);
      expect(errors).toEqual([]);
      await popup.close();
    });
  }

  test('«Hier nicht aktiv» (P05) and «Schutz pausiert» with «IT kontaktieren» (P06)', async ({ page, server, ext }) => {
    const tabId = await trackerTab(page, server, ext, HOSTS.A, 1);
    const a = await openPopup(ext, tabId, { patch: { filterable: false, url: 'chrome://extensions/' } });
    await expect(a.popup.locator('#pp-unfilterable')).toBeVisible();
    await expect(a.popup.locator('#pp-unfilterable')).toContainText('Hier nicht aktiv');
    await expect(a.popup.locator('#pp-unfilterable')).toContainText('Browser-Seiten und Stores sind für Erweiterungen gesperrt.');
    await expect(a.popup.locator('.pp-top')).toBeHidden();
    await expect(a.popup.locator('#pp-count-section')).toBeHidden();
    await expect(a.popup.locator('#pp-expand')).toBeVisible();
    await shot(a.popup, 'P05', 'light');
    await expectNoRawKeys(a.popup);
    expect(a.errors).toEqual([]);
    await a.popup.close();

    const support = 'https://intranet.example.com/it';
    const b = await openPopup(ext, tabId, { patch: { globallyDisabled: true, managed: { organizationName: 'Beispiel AG', supportUrl: support } } });
    await expect(b.popup.locator('#pp-global-off')).toBeVisible();
    await expect(b.popup.locator('#pp-global-off')).toContainText('Schutz pausiert');
    await expect(b.popup.locator('#pp-global-off')).toContainText('Ihre IT hat Bastion Shield vorübergehend ausgeschaltet.');
    const link = b.popup.locator('[data-contact="it"]');
    await expect(link).toHaveText('IT kontaktieren');
    await expect(link).toHaveAttribute('href', support);
    expect(await link.evaluate((el) => el.getBoundingClientRect().height)).toBeGreaterThanOrEqual(32);
    await shot(b.popup, 'P06', 'light');
    expect(b.errors).toEqual([]);
    await b.popup.close();

    // Without a support page or address there is no contact link.
    const c = await openPopup(ext, tabId, { patch: { globallyDisabled: true } });
    await expect(c.popup.locator('#pp-global-off')).toBeVisible();
    await expect(c.popup.locator('[data-contact="it"]')).toHaveCount(0);
    await c.popup.close();
  });

  test('counter off and «Einschalten» (P12); settings opens the expanded view', async ({ page, server, ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { ui: { activityLog: false, badge: false } } }, 3000);
    try {
      const tabId = await trackerTab(page, server, ext, HOSTS.B);
      const { popup, errors } = await openPopup(ext, tabId);
      const off = popup.locator('#pp-count-off');
      await expect(off).toBeVisible();
      await expect(off).toContainText('Zähler ausgeschaltet. Schutz ist aktiv.');
      await expect(popup.locator('#pp-savings')).toBeHidden();
      await shot(popup, 'P12', 'light');
      const on = popup.locator('#pp-count-on');
      await expect(on).toHaveText('Einschalten');
      expect(await on.evaluate((el) => el.getBoundingClientRect().height)).toBeGreaterThanOrEqual(44);
      await on.click();
      await expect(off).toBeHidden();
      await expect(popup.locator('#pp-count-body')).toBeVisible();
      await expect(popup.locator('#pp-savings')).toBeVisible();
      const cfg = await ext.send<{ settings: { ui: { activityLog: boolean } } }>({ type: 'config:get' });
      expect(cfg.settings.ui.activityLog, 'activity log switched on').toBe(true);

      // The gear opens «Diese Website» in the expanded view (reduced motion: plain page change).
      await popup.locator('#pp-expand').click();
      await popup.waitForURL(/\/ui\/panel\.html\?tabId=\d+#site$/);
      expect(errors).toEqual([]);
      await popup.close();
    } finally {
      await ext.sendAndApply({ type: 'settings:set', patch: { ui: { activityLog: true, badge: true } } }, 3000);
    }
  });

  test('nerd statusline: lookalike explained inline, no middle dots (P15)', async ({ page, server, ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: true } } }, 6000);
    try {
      const tabId = await trackerTab(page, server, ext, HOSTS.A);
      const patch = { nerd: { lookalike: { host: 'rnicrosoft-login.com', target: 'microsoft.com', reason: 'homoglyph' }, clipboardBlocked: 2 } };
      const { popup, errors } = await openPopup(ext, tabId, { patch });
      const sl = popup.locator('#pp-nerd');
      await expect(sl).toBeVisible();
      await expect(sl.locator('.pp-sl__look')).toHaveText('≠ microsoft.com');
      const card = sl.locator('.pp-sl__card');
      await expect(card).toBeVisible();
      await expect(card).toContainText('Sieht aus wie microsoft.com');
      await expect(card.locator('.pp-sl__diff')).toHaveText(['rn', '-login']);
      await expect(card).toContainText('Prüfen Sie die Adresse, bevor Sie sich anmelden.');
      expect(await sl.locator('[title*="sieht aus"]').count(), 'no tooltip carries the explanation').toBe(0);
      // clip: a disclosure explains the count inline.
      const clip = sl.locator('button', { hasText: /^clip 2$/ });
      await expect(clip).toHaveAttribute('aria-expanded', 'false');
      await clip.click();
      await expect(sl.locator('#pp-sl-clip')).toContainText('Befehle in der Zwischenablage (ClickFix) gestoppt.');
      expect(await sl.innerText()).not.toContain('·');
      await shot(popup, 'P15', 'light');
      expect(errors).toEqual([]);
      await popup.close();
    } finally {
      await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: false } } }, 6000);
    }
  });
});
