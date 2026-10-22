// Bastion Shield e2e — dashboard redesign part A (Paper DB01–DB17): the rail
// (tab 240px, panel 200px), «Übersicht», «Diese Website», «Aktivität»,
// «Filterlisten» and «Meine Listen». Every button, link and disclosure does
// something, keyboard paths work (rail arrows, dialogs trap and return
// focus), «Erneut versuchen» really retries, «Rückgängig» really restores a
// removed list, light and dark, narrow width, long hosts and 1'000+ entries
// never overflow the page, no failed extension requests and no empty labels.
// Service-worker answers for edge cases (errors, 1'200 events, long hosts,
// locked rows) are simulated in the page: window.__bsMock replaces a reply,
// window.__bsPatch merges into the real one, window.__bsLive feeds the live port.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ConsoleMessage, Page } from '@playwright/test';
import { expect, test } from '../support/fixtures.ts';

function collectErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push('pageerror: ' + String(e?.stack || e)));
  page.on('console', (m: ConsoleMessage) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  page.on('requestfailed', (r) => {
    if (r.url().startsWith('chrome-extension://')) errors.push(`requestfailed: ${r.url()} ${r.failure()?.errorText}`);
  });
  page.on('response', (r) => {
    if (r.url().startsWith('chrome-extension://') && r.status() >= 400) errors.push(`HTTP ${r.status()}: ${r.url()}`);
  });
  return errors;
}

/** Installed before the page scripts: lets a test replace or patch service-worker replies. */
function mockRuntime(): void {
  const w = window as unknown as { __bsMock?: Record<string, unknown>; __bsPatch?: Record<string, unknown>; __bsLive?: unknown[] };
  try {
    const rt = chrome.runtime as unknown as { sendMessage: (m: { type: string; before?: number; limit?: number }) => Promise<unknown>; connect: (i: unknown) => unknown };
    const orig = rt.sendMessage.bind(rt);
    const merge = (a: unknown, b: unknown): unknown => {
      if (!b || typeof b !== 'object' || Array.isArray(b)) return b;
      const o = (a && typeof a === 'object' ? a : {}) as Record<string, unknown>;
      for (const k of Object.keys(b)) o[k] = merge(o[k], (b as Record<string, unknown>)[k]);
      return o;
    };
    rt.sendMessage = (msg) => {
      const m = w.__bsMock ?? {};
      if (msg && Object.prototype.hasOwnProperty.call(m, msg.type)) {
        let r = m[msg.type] as { __page?: { t: number }[] } | unknown;
        if (r && typeof r === 'object' && Array.isArray((r as { __page?: unknown }).__page)) {
          const all = (r as { __page: { t: number }[] }).__page.filter((e) => msg.before === undefined || e.t < msg.before);
          r = { events: all.slice(0, msg.limit ?? 200) };
        }
        return Promise.resolve(JSON.parse(JSON.stringify(r)));
      }
      const pt = (w.__bsPatch ?? {})[msg?.type];
      return pt ? orig(msg).then((r) => merge(r, JSON.parse(JSON.stringify(pt)))) : orig(msg);
    };
    const oc = rt.connect.bind(rt);
    rt.connect = (info: unknown) => {
      if (!w.__bsLive) return oc(info);
      const ls: ((m: unknown) => void)[] = [];
      return {
        onMessage: { addListener: (f: (m: unknown) => void) => ls.push(f), removeListener() {} },
        onDisconnect: { addListener() {}, removeListener() {} },
        postMessage() {
          setTimeout(() => ls.forEach((f) => f({ type: 'backlog', events: w.__bsLive })), 0);
        },
        disconnect() {},
      };
    };
  } catch {
    /* not an extension page */
  }
}

interface Setup {
  mock?: Record<string, unknown>;
  patch?: Record<string, unknown>;
  live?: unknown[];
  width?: number;
  height?: number;
  dark?: boolean;
}

async function open(page: Page, origin: string, path: string, s: Setup = {}): Promise<void> {
  await page.setViewportSize({ width: s.width ?? 1280, height: s.height ?? 900 });
  await page.emulateMedia({ colorScheme: s.dark ? 'dark' : 'light', reducedMotion: 'reduce' });
  await page.addInitScript((d: Setup) => {
    const w = window as unknown as Record<string, unknown>;
    w.__bsMock = d.mock ?? {};
    if (d.patch) w.__bsPatch = d.patch;
    if (d.live) w.__bsLive = d.live;
  }, s);
  await page.addInitScript(mockRuntime);
  await page.goto(`${origin}/ui/${path}`, { waitUntil: 'load' });
  await expect(page.locator('#db-view')).toHaveAttribute('aria-busy', 'false', { timeout: 10_000 });
  await page.waitForTimeout(250);
}

async function noHorizontalOverflow(page: Page): Promise<boolean> {
  return page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
}

/** Visible buttons and links without a name (text, aria-label or title): empty or missing strings. */
async function unnamedControls(page: Page): Promise<string[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLElement>('button, a[href], [role="switch"], summary'))
      .filter((el) => el.checkVisibility())
      .filter((el) => !(el.innerText.trim() || el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || el.getAttribute('title')))
      .map((el) => el.outerHTML.slice(0, 120)),
  );
}

function dayKey(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

const LONG_HOST = 'very-long-tracking-subdomain.metrics.advertising-partner-network.example.com';

function history(days = 30): unknown {
  const out = [];
  const now = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i, 12);
    const total = 900 + ((i * 7919) % 2100);
    const byHost: Record<string, number> = { [LONG_HOST]: total };
    for (let k = 0; k < 9; k++) byHost[`h${k}.example.com`] = 100 - k;
    out.push({ day: dayKey(d), total, byKind: { blocked: total }, byCategory: { ads: total / 2, privacy: total / 3, unknown: 10 }, byHost, bySite: { '20min.ch': total, 'blick.ch': 5 }, byType: { script: total }, savedByType: { script: total } });
  }
  return { days: out, totals: { since: 0, blocked: 48213, byKind: {} } };
}

function events(n: number): unknown[] {
  const hosts = ['googletagmanager.com', 'connect.facebook.net', LONG_HOST];
  const now = Date.now();
  return Array.from({ length: n }, (_, i) => ({ t: now - i * 1000, tabId: 1, frameId: 0, kind: i % 5 ? 'blocked' : 'stripped', url: `https://${hosts[i % 3]}/p/${i}.js?${'q'.repeat(i % 2 ? 200 : 0)}`, host: hosts[i % 3], type: 'script', site: i % 4 ? '20min.ch' : 'portal.kunden-service.sparkasse-mittelland-emmental.ch', thirdParty: true }));
}

test.describe('dashboard part A', () => {
  test.beforeEach(async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { ui: { language: 'de', incidentCta: true, activityLog: true }, history: { enabled: true } } }, 3000);
  });

  test('rail: brand, search, groups, CTA; arrow keys move, Enter navigates; theme-color', async ({ ext }) => {
    const page = await ext.context.newPage();
    const errors = collectErrors(page);
    await open(page, ext.origin, 'dashboard.html#overview', { mock: { 'history:query': history() } });
    const nav = page.locator('nav.db-nav');
    expect((await nav.boundingBox())?.width).toBe(240);
    await expect(nav.locator('.db-nav__brand [translate="no"]')).toHaveText('Bastion Shield');
    await expect(nav.locator('#db-search[data-cmdk]')).toContainText('Suchen…');
    await expect(nav.locator('#db-search-kbd')).toHaveText(/^(Ctrl|⌘) K$/);
    await expect(nav.locator('.db-nav__heading')).toHaveText(['Überblick', 'Regeln', 'System']);
    await expect(nav.locator('.db-nav__foot a[data-cta="incident"]')).toBeVisible();
    expect(await page.locator('meta[name="theme-color"]').count()).toBe(2);
    await expect(page.locator('meta[name="color-scheme"]')).toHaveAttribute('content', 'light dark');

    // Keyboard: ArrowDown walks the links, Enter opens one.
    await nav.locator('.db-nav__link[data-view="overview"]').focus();
    await page.keyboard.press('ArrowDown');
    await expect(nav.locator('.db-nav__link[data-view="activity"]')).toBeFocused();
    await page.keyboard.press('ArrowDown');
    await expect(nav.locator('.db-nav__link[data-view="lists"]')).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page.locator('body')).toHaveAttribute('data-view', 'lists');
    await expect(nav.locator('.db-nav__link[data-view="lists"]')).toHaveAttribute('aria-current', 'page');
    // Navigating moves focus to the new heading; back in the rail, End jumps to the last link.
    await nav.locator('.db-nav__link[data-view="lists"]').focus();
    await page.keyboard.press('End');
    await expect(nav.locator('.db-nav__link:visible').last()).toBeFocused();
    // The search button opens the palette.
    await nav.locator('#db-search').click();
    await expect(page.locator('dialog.cmdk[open]')).toBeVisible();
    await page.keyboard.press('Escape');
    expect(errors).toEqual([]);
    await page.close();
  });

  test('overview: tiles, peak, top lists with «Alle 8 anzeigen», long hosts cut, light and dark', async ({ ext }) => {
    for (const dark of [false, true]) {
      const page = await ext.context.newPage();
      const errors = collectErrors(page);
      await open(page, ext.origin, 'dashboard.html#overview', { mock: { 'history:query': history() }, dark });
      await expect(page.locator('.ov-tile')).toHaveCount(3);
      await expect(page.locator('.ov-tile__value').first()).toHaveText(/^\d{1,3}('\d{3})*$/);
      await expect(page.locator('.ov-tile__value').nth(1)).toHaveText(/ (kB|MB|GB)$/);
      await expect(page.locator('.ov-chart .db-card__aside')).toHaveText(/^Spitze [\d']+ am /);
      await expect(page.locator('.chart__bar')).toHaveCount(30);
      const hosts = page.locator('.ov-top--hosts');
      await expect(hosts.locator('.barlist__row')).toHaveCount(4);
      const first = hosts.locator('.barlist__label').first();
      await expect(first).toHaveAttribute('title', LONG_HOST);
      await expect(first).toHaveAttribute('translate', 'no');
      expect((await first.innerText()).includes('…')).toBe(true);
      const more = hosts.locator('.ov-top__more');
      await expect(more).toHaveText('Alle 8 anzeigen');
      await more.click();
      await expect(more).toHaveAttribute('aria-expanded', 'true');
      await expect(hosts.locator('.barlist__row')).toHaveCount(8);
      await more.press('Enter');
      await expect(hosts.locator('.barlist__row')).toHaveCount(4);
      // Footer link goes to Aktivität.
      await page.locator('.ov-foot__link').click();
      await expect(page.locator('body')).toHaveAttribute('data-view', 'activity');
      const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
      expect(bg).toBe(dark ? 'rgb(23, 28, 30)' : 'rgb(255, 255, 255)');
      expect(await noHorizontalOverflow(page)).toBe(true);
      expect(await unnamedControls(page)).toEqual([]);
      expect(errors).toEqual([]);
      await page.close();
    }
  });

  test('overview: error banner retries for real; paused by IT; empty; narrow', async ({ ext }) => {
    const page = await ext.context.newPage();
    const errors = collectErrors(page);
    await open(page, ext.origin, 'dashboard.html#overview', { mock: { 'history:query': { error: 'timeout' } }, patch: { 'config:get': { managed: { protectionEnabled: false } } } });
    await expect(page.locator('.db-paused')).toContainText('Schutz pausiert');
    const banner = page.locator('.db-error');
    await expect(banner).toHaveAttribute('role', 'alert');
    await expect(banner.locator('.db-error__title')).toHaveText('Daten nicht geladen');
    // The service worker answers again: «Erneut versuchen» loads the view without a page reload.
    await page.evaluate((h) => {
      (window as unknown as { __bsMock: Record<string, unknown> }).__bsMock['history:query'] = h;
      (window as unknown as { __marker: number }).__marker = 1;
    }, history());
    await banner.locator('button', { hasText: 'Erneut versuchen' }).click();
    await expect(page.locator('.ov-tile')).toHaveCount(3);
    expect(await page.evaluate(() => (window as unknown as { __marker?: number }).__marker)).toBe(1);

    // Empty (no data yet), narrow.
    await page.evaluate(() => {
      (window as unknown as { __bsMock: Record<string, unknown> }).__bsMock['history:query'] = { days: [], totals: { since: 0, blocked: 0, byKind: {} } };
      delete (window as unknown as { __bsPatch?: unknown }).__bsPatch;
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.evaluate(() => document.dispatchEvent(new CustomEvent('db:retry')));
    await expect(page.locator('.db-empty__title')).toHaveText('Noch keine Daten');
    expect(await noHorizontalOverflow(page)).toBe(true);
    expect(errors).toEqual([]);
    await page.close();
  });

  test('activity: 1\'200 live rows capped at 500, long hosts cut, filters, no hits, pause, export dialog', async ({ ext }) => {
    const page = await ext.context.newPage();
    const errors = collectErrors(page);
    await open(page, ext.origin, 'dashboard.html#activity', { live: events(1200) });
    await expect(page.locator('.act-count')).toHaveText("Neueste 500 von 1'200 Einträgen");
    await expect(page.locator('.act-table tbody tr')).toHaveCount(500);
    const longCell = page.locator('.act-host .act-cut', { hasText: '…' }).first();
    await expect(longCell).toHaveAttribute('title', /^https:\/\/very-long-tracking/);
    expect(await noHorizontalOverflow(page)).toBe(true);

    // Host filter without hits, then «Filter zurücksetzen».
    await page.locator('input[placeholder="Host filtern…"]').fill('xyz-tracker.ch');
    await expect(page.locator('.act-nohits__title')).toHaveText('Keine Einträge für «xyz-tracker.ch»');
    await page.locator('.act-nohits button').click();
    await expect(page.locator('.act-table tbody tr')).toHaveCount(500);
    await expect(page.locator('input[placeholder="Host filtern…"]')).toHaveValue('');

    // Pause toggles its label and pressed state.
    const pause = page.locator('.act-pause');
    await pause.click();
    await expect(pause).toHaveAttribute('aria-pressed', 'true');
    await expect(pause).toContainText('Fortsetzen');
    await pause.click();
    await expect(pause).toHaveAttribute('aria-pressed', 'false');

    // «Exportieren…» opens a dialog; focus starts on «Abbrechen» and comes back.
    const exp = page.locator('.act-bar button', { hasText: 'Exportieren…' });
    await exp.click();
    const dlg = page.locator('dialog.dialog[open]');
    await expect(dlg).toContainText('Aktivität exportieren');
    await expect(dlg.locator('[data-dialog="cancel"]')).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(exp).toBeFocused();

    // «Ansicht leeren» empties the live view.
    await page.locator('.act-bar button', { hasText: 'Ansicht leeren' }).click();
    await expect(page.locator('.act-wait__title')).toHaveText('Warten auf Aktivität');

    // Narrow: the table scrolls inside its box, the page does not.
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await noHorizontalOverflow(page)).toBe(true);
    expect(await unnamedControls(page)).toEqual([]);
    expect(errors).toEqual([]);
    await page.close();
  });

  test('activity: history loads older pages; «Verlauf löschen…» dialog traps and returns focus', async ({ ext }) => {
    const page = await ext.context.newPage();
    const errors = collectErrors(page);
    await open(page, ext.origin, 'dashboard.html#activity', { mock: { 'history:events': { __page: events(450) }, 'history:clear': {} }, live: [] });
    await page.locator('.act-mode [data-value="history"]').click();
    await expect(page.locator('.act-count')).toHaveText('200 Einträge geladen');
    const older = page.locator('.act-more button', { hasText: 'Ältere Einträge laden' });
    await older.click();
    await expect(page.locator('.act-count')).toHaveText('400 Einträge geladen');
    await older.click();
    await expect(page.locator('.act-count')).toHaveText('450 Einträge geladen');
    await expect(page.locator('.act-more')).toBeHidden();

    const clear = page.locator('.act-bar button', { hasText: 'Verlauf löschen…' });
    await expect(clear).toHaveClass(/btn--danger/);
    await clear.click();
    const dlg = page.locator('dialog.dialog[open]');
    await expect(dlg.locator('[data-dialog="confirm"]')).toHaveText('Verlauf löschen');
    await expect(dlg.locator('[data-dialog="cancel"]')).toHaveText('Verlauf behalten');
    await expect(dlg.locator('[data-dialog="cancel"]')).toBeFocused();
    // Focus stays inside the dialog.
    for (let i = 0; i < 4; i++) {
      await page.keyboard.press('Tab');
      // The page behind the modal is inert: focus is in the dialog or has left for the browser UI, never on the page.
      expect(await page.evaluate(() => { const a = document.activeElement; return !a || a === document.body || !!a.closest('dialog[open]'); })).toBe(true);
    }
    await dlg.locator('[data-dialog="cancel"]').click();
    await expect(clear).toBeFocused();
    await expect(page.locator('.act-table tbody tr')).toHaveCount(450);
    await clear.click();
    await page.locator('dialog.dialog[open] [data-dialog="confirm"]').click();
    await expect(page.locator('.toast').last()).toContainText('Verlauf gelöscht');
    expect(errors).toEqual([]);
    await page.close();
  });

  test('activity: log off banner switches the log on', async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { ui: { activityLog: false } } }, 3000);
    const page = await ext.context.newPage();
    const errors = collectErrors(page);
    await open(page, ext.origin, 'dashboard.html#activity', { live: [] });
    await expect(page.locator('.act-logoff__title')).toHaveText('Protokoll ausgeschaltet');
    await page.locator('.act-logoff__on').click();
    await expect(page.locator('.act-logoff')).toHaveCount(0);
    const cfg = await ext.send<{ settings: { ui: { activityLog: boolean } } }>({ type: 'config:get' });
    expect(cfg.settings.ui.activityLog).toBe(true);
    expect(errors).toEqual([]);
    await page.close();
  });

  test('filter lists: budget disclosure, groups open and close, details, locked rows, dark', async ({ ext }) => {
    for (const dark of [false, true]) {
      const page = await ext.context.newPage();
      const errors = collectErrors(page);
      await open(page, ext.origin, 'dashboard.html#lists', { dark, patch: { 'lists:get': { budget: { used: 29140 } } } });
      const budget = page.locator('.lists-budget');
      await expect(budget.locator('.lists-meter__note').first()).toHaveText(/^97 % - Weitere Listen können vom Browser abgelehnt werden\.$/);
      const what = budget.locator('.db-card__head button');
      await expect(what).toHaveText('Was ist das?');
      await what.click();
      await expect(what).toHaveAttribute('aria-expanded', 'true');
      await expect(budget.locator('.lists-budget__more')).toBeVisible();
      await expect(what).toHaveText('Erklärung ausblenden');
      const groups = page.locator('details.lists-group');
      expect(await groups.count()).toBeGreaterThan(2);
      await expect(groups.first()).toHaveAttribute('open', '');
      await groups.nth(1).locator('summary').click();
      await expect(groups.nth(1)).toHaveAttribute('open', '');
      const details = groups.first().locator('.lists-row__meta button').first();
      await details.click();
      await expect(details).toHaveText('Details ausblenden');
      await expect(groups.first().locator('.lists-row__more').first()).toBeVisible();
      expect(await noHorizontalOverflow(page)).toBe(true);
      expect(await unnamedControls(page)).toEqual([]);
      expect(errors).toEqual([]);
      await page.close();
    }
    // Locked by the organisation: every row says so, switches are disabled.
    const page = await ext.context.newPage();
    await open(page, ext.origin, 'dashboard.html#lists', { patch: { 'config:get': { locked: ['lists'] } } });
    await expect(page.locator('.lists-locked')).toBeVisible();
    await expect(page.locator('details.lists-group').first().locator('.db-locked').first()).toContainText('Von Ihrer Organisation festgelegt');
    await expect(page.locator('details.lists-group').first().locator('[role="switch"]').first()).toBeDisabled();
    await page.close();
  });

  test('my lists: validation below the field, rename with counter, remove and «Rückgängig» restores', async ({ ext }) => {
    // A real list in the service worker, switched off (the undo must keep that).
    const before = await ext.send<{ lists: { id: string }[] }>({ type: 'mylists:get' });
    for (const l of before.lists ?? []) await ext.send({ type: 'mylists:remove', id: l.id });
    const added = await ext.send<{ lists: { id: string; title: string }[] }>({ type: 'mylists:add', file: { name: 'e2e-liste.txt', text: '! Title: E2E Liste\n||e2e-undo.example^\n' } });
    const id = added.lists[0].id;
    await ext.send({ type: 'mylists:set', id, enabled: false });

    const page = await ext.context.newPage();
    const errors = collectErrors(page);
    await open(page, ext.origin, 'dashboard.html#lists');
    const card = page.locator('.my-lists');
    await expect(card.locator('.db-card__aside')).toHaveText('1 von 20');
    const row = card.locator(`[data-list-id="${id}"]`);
    await expect(row).toBeVisible();

    // URL checks: the error sits right below the field and names the fix.
    const input = card.locator('.my-lists__url .field__input');
    await input.fill('http://example.org/list.txt');
    await card.locator('.my-lists__url button[type="submit"]').click();
    await expect(card.locator('.my-lists__url .field__error')).toHaveText('Geben Sie eine Adresse ein, die mit https:// beginnt.');
    await expect(input).toHaveAttribute('aria-invalid', 'true');
    await expect(input).toBeFocused();
    await input.fill('https://example.org/list.txt');
    await expect(card.locator('.my-lists__url .field__error')).toBeHidden();

    // A file of the wrong type is named with «Andere Datei…».
    const chooser = page.waitForEvent('filechooser');
    await card.locator('.my-lists__url button', { hasText: 'Datei hochladen…' }).click();
    await (await chooser).setFiles({ name: 'kundenliste.xlsx', mimeType: 'application/vnd.ms-excel', buffer: Buffer.from('PK\u0003\u0004') });
    await expect(card.locator('.my-lists__issue')).toContainText('Das ist keine Filterliste. Erlaubt sind .txt, .list und .hosts.');
    await expect(card.locator('.my-lists__issue button')).toHaveText('Andere Datei…');

    // A file with the same title asks «Inhalt ersetzen» / «Als neue Liste hinzufügen» (D05); cancel keeps everything.
    const chooser2 = page.waitForEvent('filechooser');
    await card.locator('.my-lists__url button', { hasText: 'Datei hochladen…' }).click();
    await (await chooser2).setFiles({ name: 'neu.txt', mimeType: 'text/plain', buffer: Buffer.from('! Title: E2E Liste\n||other.example^\n') });
    const d05 = page.locator('dialog.dialog[open]');
    await expect(d05.locator('[data-dialog="replace"]')).toHaveText('Inhalt ersetzen');
    await expect(d05.locator('[data-dialog="new"]')).toHaveText('Als neue Liste hinzufügen');
    await expect(d05.locator('[data-dialog="cancel"]')).toBeFocused();
    await d05.locator('[data-dialog="cancel"]').click();
    await expect(card.locator('.db-card__aside')).toHaveText('1 von 20');

    // Rename: counter from 80 % of 120.
    await row.locator('[data-action="rename"]').click();
    const name = row.locator('.my-lists__rename .field__input');
    await expect(name).toBeFocused();
    await name.fill('x'.repeat(95));
    await expect(row.locator('.my-lists__rename .field__counter')).toHaveText('');
    await name.fill(`Firmenliste ${'y'.repeat(100)}`);
    await expect(row.locator('.my-lists__rename .field__counter')).toHaveText(/^\d+ \/ 120$/);
    await name.fill('');
    await row.locator('.my-lists__rename button[type="submit"]').click();
    await expect(row.locator('.my-lists__rename .field__error')).toHaveText('Geben Sie einen Namen ein.');
    await name.fill('Firmenliste Bern');
    await row.locator('.my-lists__rename button[type="submit"]').click();
    await expect(row.locator('.lists-row__name')).toHaveText('Firmenliste Bern');

    // Remove → toast with «Rückgängig» → the list is back, still switched off.
    await row.locator('[data-action="remove"]').click();
    await expect(row).toHaveCount(0);
    const toast = page.locator('.toast', { hasText: 'entfernt' });
    await toast.locator('.toast__action').click();
    await expect(card.locator(`[data-list-id="${id}"]`)).toBeVisible();
    await expect(card.locator(`[data-list-id="${id}"] [role="switch"]`)).toHaveAttribute('aria-checked', 'false');
    const after = await ext.send<{ lists: { id: string; enabled: boolean; title: string }[] }>({ type: 'mylists:get' });
    expect(after.lists.map((l) => [l.id, l.enabled, l.title])).toEqual([[id, false, 'Firmenliste Bern']]);
    expect(await unnamedControls(page)).toEqual([]);
    expect(errors).toEqual([]);
    await ext.send({ type: 'mylists:remove', id });
    await page.close();
  });

  test('my lists: empty, full 20/20 and locked by IT', async ({ ext }) => {
    const mk = (n: number, locked = false): unknown => ({
      lists: Array.from({ length: n }, (_, i) => ({ id: `l${String(i).padStart(9, '0')}`, slot: i, title: `Liste ${i}`, source: 'file', fileName: `l${i}.txt`, enabled: true, autoUpdate: false, added: 1, updated: 1, checked: 1, bytes: 10, filters: 3, report: { network: 3, cosmetic: 0, scriptletsIgnored: 0, errors: [] } })),
      locked,
      maxLists: 20,
      maxBytes: 10_000_000,
    });
    const page = await ext.context.newPage();
    await open(page, ext.origin, 'dashboard.html#lists', { mock: { 'mylists:get': mk(0) } });
    await expect(page.locator('.my-lists__empty-title')).toHaveText('Noch keine eigenen Listen');
    await page.close();

    const full = await ext.context.newPage();
    await open(full, ext.origin, 'dashboard.html#lists', { mock: { 'mylists:get': mk(20) } });
    await expect(full.locator('.my-lists .field__hint')).toHaveText('Höchstens 20 Listen. Entfernen Sie eine, um Platz zu schaffen.');
    await expect(full.locator('.my-lists__url .field__input')).toBeDisabled();
    await expect(full.locator('.my-lists .lists-list > li')).toHaveCount(5);
    await full.locator('.my-lists__all').click();
    await expect(full.locator('.my-lists .lists-list > li')).toHaveCount(20);
    await full.close();

    const locked = await ext.context.newPage();
    await open(locked, ext.origin, 'dashboard.html#lists', { mock: { 'mylists:get': mk(1, true) } });
    await expect(locked.locator('.my-lists__lockaside')).toHaveText('Von Ihrer Organisation festgelegt');
    await expect(locked.locator('.my-lists [role="switch"]').first()).toBeDisabled();
    await expect(locked.locator('.my-lists__url')).toHaveCount(0);
    await locked.close();
  });

  test('panel (760×560): 200px rail, overview, activity, lists and «Diese Website» states', async ({ ext }) => {
    const page = await ext.context.newPage();
    const errors = collectErrors(page);
    await page.addInitScript(() => {
      window.close = () => undefined;
    });
    await open(page, ext.origin, 'panel.html#overview', { width: 760, height: 560, mock: { 'history:query': history() }, live: events(1200) });
    expect((await page.locator('nav.db-nav').boundingBox())?.width).toBe(200);
    await expect(page.locator('#db-collapse')).toContainText('Verkleinern');
    await expect(page.locator('.db-nav__dash')).toContainText('Dashboard öffnen');
    await expect(page.locator('.db-nav__link[data-view="filters"]')).toHaveAttribute('data-open-tab', 'filters');
    await expect(page.locator('.ov-tile')).toHaveCount(3);
    await expect(page.locator('.ov-chart .db-card__aside')).toHaveText(/^Spitze [\d']+$/);
    await expect(page.locator('.ov-top--hosts .db-card__aside button')).toHaveText('Alle');
    expect(await noHorizontalOverflow(page)).toBe(true);

    await page.locator('.db-nav__link[data-view="activity"]').click();
    await expect(page.locator('.act-count')).toHaveText("Neueste 500 von 1'200");
    await expect(page.locator('.act-item')).toHaveCount(500);
    await expect(page.locator('.act-pause')).toHaveAttribute('aria-label', 'Pausieren');
    await page.locator('input[placeholder="Host oder Website filtern…"]').fill('sparkasse');
    await expect(page.locator('.act-item').first()).toContainText('portal');
    expect(await noHorizontalOverflow(page)).toBe(true);

    await page.locator('.db-nav__link[data-view="lists"]').click();
    await expect(page.locator('.lists-row--compact').first()).toBeVisible();
    await expect(page.locator('.lists-mine__open')).toHaveText('Im Tab bearbeiten');
    expect(await unnamedControls(page)).toEqual([]);
    expect(errors).toEqual([]);
    await page.close();

    // «Diese Website»: long host, protection off and locked (DB07).
    const site = await ext.context.newPage();
    await open(site, ext.origin, 'panel.html#site', {
      width: 760,
      height: 560,
      patch: { 'popup:state': { host: 'portal.kunden-service.sparkasse-mittelland-emmental.ch', site: 'sparkasse-mittelland-emmental.ch', url: 'https://x/', filterable: true, counting: true, siteSettings: { enabled: false }, locks: { mode: true, settings: true, siteToggle: false } } },
    });
    await expect(site.locator('.site-host')).toHaveText('portal.kunden-service.sparkasse-mittelland-emmental.ch');
    await expect(site.locator('.site-host')).toHaveAttribute('translate', 'no');
    await expect(site.locator('.site-toggle__state')).toHaveText('Schutz aus');
    await expect(site.locator('.site-off__title')).toHaveText('Auf dieser Website ist nichts blockiert');
    await expect(site.locator('.site-locked')).toContainText('Modus und Skripte sind von Ihrer Organisation festgelegt.');
    await expect(site.locator('.site-settings [role="switch"]')).toBeDisabled();
    await expect(site.locator('.site-report')).toContainText('Seite defekt? Melden…');
    await site.locator('.site-rules > summary').click();
    await expect(site.locator('.site-rules')).toHaveAttribute('open', '');
    expect(await noHorizontalOverflow(site)).toBe(true);
    await site.close();
  });

  test('panel «Diese Website» error: «Erneut versuchen» loads it again', async ({ ext }) => {
    const page = await ext.context.newPage();
    await open(page, ext.origin, 'panel.html?tabId=999999#site', { width: 760, height: 560, mock: { 'popup:state': { error: 'no-tab' } } });
    await expect(page.locator('.db-error__title')).toHaveText('Daten nicht geladen');
    await page.evaluate(() => {
      (window as unknown as { __bsMock: Record<string, unknown> }).__bsMock['popup:state'] = { tabId: 999999, host: '20min.ch', site: '20min.ch', url: 'https://20min.ch/', filterable: true, counting: false };
    });
    await page.locator('.db-error button').click();
    await expect(page.locator('.site-host')).toHaveText('20min.ch');
    await page.close();
  });
});
