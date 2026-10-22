// Bastion Shield e2e — dashboard rule and system views (phase 5b):
// «Eigene Filter», «Website-Ausnahmen», «Datenschutz», «Einstellungen»,
// «Über» and «Entwicklertools» in the tab (ui/dashboard.html#<view>) and the
// expanded popup (ui/panel.html). Every control does what it says, dialogs
// trap and return focus, a removed site comes back with «Rückgängig», the
// error banner retries for real, and light, dark, narrow and very long
// content never overflow. A second browser with the managed-policy shim
// checks the locked states. BASTION_SHOTS=<dir> also saves the artboard
// screenshots (DB20–DB43).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { mkdirSync } from 'node:fs';
import path from 'node:path';
import type { BrowserContext, Page } from '@playwright/test';
import { expect, test } from '../support/fixtures.ts';
import { ExtensionHarness } from '../support/extension.ts';
import { setManagedPolicy } from '../support/managed.ts';
import { poll } from '../support/pages.ts';

const SHOTS = process.env.BASTION_SHOTS;
const ONLY = (process.env.BASTION_SHOTS_ONLY ?? '').split(',').filter(Boolean);

function filterText(lines: number): string {
  const base = [
    '! Werbung auf Schweizer News-Seiten',
    '||ads.example-network.com^',
    '||adserver.ch-media.example^$third-party',
    '20min.ch##.teaser--sponsored',
    'watson.ch##.native-ad',
    'blick.ch##div[data-ad-slot]',
    '! Tracker',
    '||track.verylongtrackingdomainname-for-analytics-and-measurement.example.com^',
    '||metrics.example.com^$script',
    '@@||postfinance.ch^$document',
    'nzz.ch##.paywall-teaser',
    '||cdn.example.org/fingerprint.js$script',
    'srf.ch##.cookie-hint',
    '||pixel.example.net^$image',
  ];
  const out: string[] = [];
  for (let i = 0; i < lines; i++) out.push(i < base.length ? base[i] : `||host-${i}.example.com^`);
  return out.join('\n');
}

type Sites = Record<string, { enabled?: boolean; mode?: 'standard' | 'aggressive'; blockScripts?: boolean; fingerprinting?: 'off' | 'standard' | 'strict' }>;

function sampleSites(): Sites {
  return {
    '20min.ch': { fingerprinting: 'standard' },
    'portal.kunden-service-region-emmental-mittelland.ch': { enabled: false, mode: 'aggressive' },
    'nzz.ch': { blockScripts: true, fingerprinting: 'strict' },
    'srf.ch': { mode: 'standard' },
  };
}

function manySites(n: number): Sites {
  const out: Sites = { 'bank-now.ch': { blockScripts: true }, 'ebanking.raiffeisen.ch': { enabled: false, mode: 'aggressive' }, 'e-banking.zkb.ch': { enabled: false } };
  for (let i = 0; Object.keys(out).length < n; i++) out[`site-${String(i).padStart(4, '0')}.example.ch`] = i % 3 ? { blockScripts: true } : { enabled: false };
  return out;
}

interface Shot {
  name: string;
  url: string;
  w?: number;
  h?: number;
  full?: boolean;
  before?: () => Promise<void>;
  act?: (p: Page) => Promise<void>;
}

test.describe('dashboard rule and system views', () => {
  test('screenshots', async ({ ext }) => {
    test.skip(!SHOTS, 'BASTION_SHOTS not set');
    test.setTimeout(300_000);
    mkdirSync(SHOTS!, { recursive: true });
    await ext.sendAndApply({ type: 'settings:set', patch: { ui: { language: 'de' } } }, 3000);
    const shots: Shot[] = [
      {
        name: 'DB20',
        url: 'dashboard.html#filters',
        before: async () => void (await ext.send({ type: 'custom:set', text: filterText(1201) })),
        act: async (p) => {
          await p.locator('.cf-field').click();
          await p.keyboard.press('Control+End');
          await p.keyboard.type('\nsrf.ch##.x\n||new.example^\n');
          await p.waitForTimeout(500);
        },
      },
      {
        name: 'DB21',
        url: 'dashboard.html#filters',
        act: async (p) => {
          await p.locator('.cf-field').click();
          await p.keyboard.press('Control+Home');
          await p.keyboard.type('watson.ch##[.native-ad\n@@||postfinance.ch^$documnet\n');
          await p.waitForTimeout(500);
        },
      },
      { name: 'DB26', url: 'dashboard.html#sites', before: async () => void (await ext.send({ type: 'sites:set', sites: {} })) },
      {
        name: 'DB24',
        url: 'dashboard.html#sites',
        before: async () => void (await ext.send({ type: 'sites:set', sites: sampleSites() })),
        act: async (p) => {
          await p.locator('.sites-add__input').fill('watson.ch');
          await p.keyboard.press('Enter');
          await p.waitForTimeout(400);
        },
      },
      {
        name: 'DB25',
        url: 'dashboard.html#sites',
        before: async () => void (await ext.send({ type: 'sites:set', sites: manySites(1248) })),
        act: async (p) => {
          await p.locator('.sites-search__input').fill('bank');
          await p.locator('.sites-add__input').fill('https://bank-login');
          await p.keyboard.press('Enter');
          await p.waitForTimeout(400);
        },
      },
      { name: 'DB27', url: 'dashboard.html#privacy', full: true },
      { name: 'DB28', url: 'dashboard.html#settings', full: true, before: async () => void (await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: true, protectedDomains: [] } } }, 3000)),
        act: async (p) => {
          await p.locator('.nerd-domains').fill(['postfinance.ch', 'ubs.com', 'raiffeisen.ch', 'meine bank', 'zkb.ch', 'ebanking.blkb'].join('\n'));
          await p.locator('.nerd-domains__edit .btn').click();
          await p.waitForTimeout(600);
        } },
      { name: 'DB29', url: 'dashboard.html#settings', full: true },
      { name: 'DB30', url: 'dashboard.html#about', full: true },
      {
        name: 'DB31',
        url: 'dashboard.html#lab',
        act: async (p) => {
          await p.locator('.lab-play textarea').first().fill(['||doubleclick.net^', '||track.example.com^$script', 'example.com##.newsletter-popup', '||example.org^$documnet'].join('\n'));
          await p.keyboard.press('Control+Enter');
          await p.waitForTimeout(1500);
        },
      },
      { name: 'DB32', url: 'dashboard.html#lab', before: async () => void (await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: false } } }, 3000)) },
      { name: 'DB40', url: 'panel.html#sites', w: 760, h: 560 },
      { name: 'DB41', url: 'panel.html#privacy', w: 760, h: 560 },
      { name: 'DB42', url: 'panel.html#settings', w: 760, h: 560 },
      { name: 'DB43', url: 'panel.html#about', w: 760, h: 560 },
    ];
    for (const s of shots) {
      if (ONLY.length && !ONLY.includes(s.name)) continue;
      for (const scheme of ['light', 'dark'] as const) {
        await s.before?.();
        const page = await ext.context.newPage();
        page.on('pageerror', (e) => console.log(s.name, 'pageerror', e.message));
        await page.setViewportSize({ width: s.w ?? 1280, height: s.h ?? 840 });
        await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
        await page.goto(`${ext.origin}/ui/${s.url}`);
        await page.waitForTimeout(700);
        await s.act?.(page);
        await page.screenshot({ path: path.join(SHOTS!, `${s.name}-${scheme}.png`), fullPage: s.full ?? false });
        await page.close();
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Behaviour
// ---------------------------------------------------------------------------

const VIEWS = ['filters', 'sites', 'privacy', 'settings', 'about', 'lab'] as const;
/** A message key that leaked into the UI instead of its text. */
const RAW_KEY = /\b(cf|sites|set|priv|about|nerd|panel|action)[A-Z][A-Za-z]+\b|__MSG_/;

interface Watched {
  page: Page;
  errors: string[];
}

/** A tab in the extension context that records page errors, console errors and failed extension requests. */
async function openPage(context: BrowserContext, opts: { fail?: Record<string, number>; width?: number; height?: number; dark?: boolean } = {}): Promise<Watched> {
  const page = await context.newPage();
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error' && !/simulated/.test(m.text())) errors.push(`console: ${m.text()}`);
  });
  page.on('requestfailed', (r) => {
    if (r.url().startsWith('chrome-extension://')) errors.push(`requestfailed: ${r.url()}`);
  });
  page.on('response', (r) => {
    if (r.url().startsWith('chrome-extension://') && r.status() >= 400) errors.push(`${r.status()}: ${r.url()}`);
  });
  await page.setViewportSize({ width: opts.width ?? 1280, height: opts.height ?? 900 });
  await page.emulateMedia({ colorScheme: opts.dark ? 'dark' : 'light', reducedMotion: 'reduce' });
  if (opts.fail) {
    // The next N answers of a message type fail as if the service worker had not answered.
    await page.addInitScript((fail: Record<string, number>) => {
      const left = { ...fail };
      const rt = chrome.runtime;
      const orig = rt.sendMessage.bind(rt) as (m: unknown) => Promise<unknown>;
      (rt as unknown as { sendMessage: (m: { type?: string }) => Promise<unknown> }).sendMessage = (m) => {
        if (m && typeof m.type === 'string' && (left[m.type] ?? 0) > 0) {
          left[m.type] -= 1;
          return Promise.resolve({ error: 'simulated' });
        }
        return orig(m);
      };
    }, opts.fail);
  }
  return { page, errors };
}

async function ready(page: Page): Promise<void> {
  await page.locator('[aria-busy="false"]#db-view').waitFor({ timeout: 10_000 }).catch(() => undefined);
  await page.locator('h1').first().waitFor();
  await page.waitForTimeout(150);
}

/** No horizontal page scroll and no element wider than its scroll container. */
async function noOverflow(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const out: string[] = [];
    const doc = document.scrollingElement as HTMLElement;
    if (doc.scrollWidth > doc.clientWidth + 1) out.push(`page scrolls sideways: ${doc.scrollWidth} > ${doc.clientWidth}`);
    const view = document.querySelector<HTMLElement>('#db-view');
    if (view && view.scrollWidth > view.clientWidth + 1) out.push(`view overflows: ${view.scrollWidth} > ${view.clientWidth}`);
    if (out.length) {
      const vw = doc.clientWidth;
      for (const el of Array.from(document.querySelectorAll<HTMLElement>('body *'))) {
        const r = el.getBoundingClientRect();
        if (r.right > vw + 1 && r.width > 0 && !el.closest('.sites-scroll, .about-scroll, pre, textarea, .db-nav, nav')) {
          out.push(`${el.tagName.toLowerCase()}.${el.className} ${Math.round(r.right)}`);
          if (out.length > 8) break;
        }
      }
    }
    return out;
  });
}

async function noRawKeys(page: Page): Promise<void> {
  const text = await page.locator('body').innerText();
  expect.soft(text.match(RAW_KEY)?.[0] ?? null, 'no raw i18n key visible').toBeNull();
  expect.soft(text.includes('\u00b7'), 'no middle dot separator').toBe(false);
}

async function pickFile(page: Page, click: () => Promise<void>, name: string, text: string): Promise<void> {
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), click()]);
  await chooser.setFiles({ name, mimeType: name.endsWith('.json') ? 'application/json' : 'text/plain', buffer: Buffer.from(text) });
}

test.describe('dashboard rule and system views: behaviour', () => {
  test.beforeAll(async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { ui: { language: 'de' }, nerd: { enabled: false } } }, 3000);
  });
  test.afterAll(async ({ ext }) => {
    await ext.send({ type: 'sites:set', sites: {} });
    await ext.send({ type: 'custom:set', text: '' });
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: false, protectedDomains: [] } } }, 3000);
  });

  test('every view renders in the tab and the expanded popup, light and dark, wide and narrow, without overflow', async ({ ext }) => {
    test.setTimeout(240_000);
    await ext.send({ type: 'sites:set', sites: manySites(1248) });
    await ext.send({ type: 'custom:set', text: `${filterText(300)}\n||${'very-long-label-'.repeat(12)}example.com^$script,domain=${'x'.repeat(200)}.ch` });
    for (const dark of [false, true]) {
      for (const width of [1280, 390]) {
        const { page, errors } = await openPage(ext.context, { dark, width });
        for (const v of VIEWS) {
          await page.goto(`${ext.origin}/ui/dashboard.html#${v}`);
          await ready(page);
          expect.soft(await noOverflow(page), `#${v} ${dark ? 'dark' : 'light'} ${width}px`).toEqual([]);
          await noRawKeys(page);
        }
        expect.soft(errors, `errors ${dark ? 'dark' : 'light'} ${width}px`).toEqual([]);
        await page.close();
      }
    }
    const { page, errors } = await openPage(ext.context, { width: 760, height: 560 });
    await page.addInitScript(() => {
      window.close = () => undefined;
    });
    for (const v of ['sites', 'privacy', 'settings', 'about']) {
      await page.goto(`${ext.origin}/ui/panel.html#${v}`);
      await ready(page);
      expect.soft(await noOverflow(page), `panel #${v}`).toEqual([]);
      await noRawKeys(page);
    }
    // Sections that need the tab say so with a working button.
    await page.goto(`${ext.origin}/ui/panel.html#settings`);
    await ready(page);
    await expect(page.locator('[data-open-tab="settings"]')).toBeVisible();
    await expect(page.locator('.nerd-panel')).toHaveCount(0);
    await page.goto(`${ext.origin}/ui/panel.html#sites`);
    await ready(page);
    await expect(page.locator('[data-open-tab="sites"]')).toBeVisible();
    await expect(page.locator('.sites-li').first()).toBeVisible();
    expect.soft(errors, 'panel errors').toEqual([]);
    await page.close();
  });

  test('Eigene Filter: counter, live check, dirty bar, discard, apply, too big, leave dialog', async ({ ext }) => {
    test.setTimeout(180_000);
    await ext.send({ type: 'custom:set', text: '||ads.example.com^' });
    const { page, errors } = await openPage(ext.context);
    await page.goto(`${ext.origin}/ui/dashboard.html#filters`);
    await ready(page);
    const field = page.locator('.cf-field');
    await expect(page.locator('.cf-count')).toHaveText(/^1 Zeile - 1\u00a0KB von 1\u00a0MB$/);
    await expect(page.locator('.cf-bar')).toBeHidden();

    // Two invalid lines: flagged with line number and reason, bar counts changes and errors.
    await field.click();
    await page.keyboard.press('Control+End');
    await page.keyboard.type('\nwatson.ch##[.native-ad\n@@||postfinance.ch^$documnet');
    await expect(page.locator('.cf-bar')).toBeVisible();
    await expect(page.locator('.cf-bar__text')).toHaveText('2 Änderungen - 2 Zeilen fehlerhaft');
    await expect(page.locator('.cf-err')).toHaveCount(2);
    await expect(page.locator('.cf-err').nth(1)).toContainText('Meinten Sie «document»?');
    await expect(page.locator('.cf-gutter__bad')).toHaveCount(2);
    await page.locator('.cf-err__line').first().click();
    expect(await page.evaluate(() => document.activeElement?.classList.contains('cf-field'))).toBe(true);

    // Verwerfen restores the applied text.
    await page.locator('.cf-discard').click();
    await expect(field).toHaveValue('||ads.example.com^');
    await expect(page.locator('.cf-bar')).toBeHidden();

    // Filter anwenden saves (button and Ctrl S).
    await field.fill('||ads.example.com^\n||tracker.example.org^');
    await expect(page.locator('.cf-bar__text')).toHaveText('1 Änderung nicht angewendet');
    await page.locator('.cf-apply').click();
    await expect(page.locator('.cf-bar')).toBeHidden();
    expect((await ext.send<{ text: string }>({ type: 'custom:get' })).text).toBe('||ads.example.com^\n||tracker.example.org^');
    await field.fill('||a.example^');
    await field.press('Control+s');
    await expect(page.locator('.cf-bar')).toBeHidden();
    expect((await ext.send<{ text: string }>({ type: 'custom:get' })).text).toBe('||a.example^');

    // Over 1 MB: banner, red counter, «Zu gross zum Anwenden», apply disabled.
    await field.evaluate((el: HTMLTextAreaElement) => {
      el.value = '||a.example^\n'.repeat(80_000);
      el.dispatchEvent(new Event('input'));
    });
    await expect(page.locator('.notice--danger[role="alert"]')).toContainText('Zu viele Filter: 1\u00a0MB von 1\u00a0MB');
    await expect(page.locator('.cf-count')).toHaveClass(/cf-count--bad/);
    await expect(page.locator('.cf-bar__text')).toHaveText('Zu gross zum Anwenden');
    await expect(page.locator('.cf-apply')).toBeDisabled();
    expect(await noOverflow(page)).toEqual([]);

    // Leaving with unapplied changes asks (D06): Escape stays, focus comes back; «Änderungen verwerfen» leaves.
    await field.evaluate((el: HTMLTextAreaElement) => {
      el.value = '||b.example^';
      el.dispatchEvent(new Event('input'));
    });
    await field.focus();
    await page.evaluate(() => (location.hash = '#sites'));
    const dlg = page.locator('dialog.dialog');
    await expect(dlg).toBeVisible();
    await expect(dlg.locator('[data-dialog="apply"]')).toHaveText('Filter anwenden');
    await expect(dlg.locator('[data-dialog="discard"]')).toHaveText('Änderungen verwerfen');
    expect(await page.evaluate(() => (document.activeElement as HTMLElement | null)?.dataset.dialog)).toBe('cancel');
    // Focus stays inside the dialog.
    for (let i = 0; i < 4; i++) {
      await page.keyboard.press('Tab');
      }
    expect(await page.evaluate(() => !!document.activeElement?.closest('dialog'))).toBe(true);
    await page.keyboard.press('Escape');
    await expect(dlg).toHaveCount(0);
    expect(page.url()).toMatch(/#filters$/);
    expect(await page.evaluate(() => document.activeElement?.classList.contains('cf-field'))).toBe(true);
    await page.evaluate(() => (location.hash = '#sites'));
    await page.locator('dialog.dialog [data-dialog="discard"]').click();
    await expect(page.locator('body')).toHaveAttribute('data-view', 'sites');
    expect((await ext.send<{ text: string }>({ type: 'custom:get' })).text).toBe('||a.example^');

    // Import: a file that is no filter list says so and offers another file.
    await page.goto(`${ext.origin}/ui/dashboard.html#filters`);
    await ready(page);
    await pickFile(page, () => page.locator('.db-head__actions .btn').first().click(), 'kunden-liste.xlsx', 'PK\u0003\u0004 binary');
    await expect(page.locator('.toast').last()).toContainText('«kunden-liste.xlsx» ist keine Filterliste (.txt) und keine Sicherung.');
    await pickFile(page, () => page.locator('.toast__action').last().click(), 'meine.txt', '||imported.example^\n');
    await expect(field).toHaveValue(/imported\.example/);
    await page.locator('.cf-discard').click();
    // Export downloads the applied text.
    const [dl] = await Promise.all([page.waitForEvent('download'), page.locator('.db-head__actions .btn').nth(1).click()]);
    expect(dl.suggestedFilename()).toMatch(/^bastion-shield-filters-\d{4}-\d\d-\d\d\.txt$/);
    // The builder disclosure opens with the keyboard.
    await page.locator('.cfb__summary').focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('.cfb')).toHaveAttribute('open', '');
    await page.locator('.cfb input.input').first().fill('ads.example.net');
    await page.locator('.cfb-row .btn').click();
    await expect(field).toHaveValue(/\|\|ads\.example\.net\^/);
    await page.locator('.cf-discard').click();
    expect(errors).toEqual([]);
    await page.close();
  });

  test('Website-Ausnahmen: error under the field, add, search counter, remove with undo, import preview', async ({ ext }) => {
    await ext.send({ type: 'sites:set', sites: manySites(1248) });
    const { page, errors } = await openPage(ext.context);
    await page.goto(`${ext.origin}/ui/dashboard.html#sites`);
    await ready(page);
    const input = page.locator('.sites-add__input');
    await input.fill('https://bank-login');
    await input.press('Enter');
    await expect(page.locator('.sites-add__msg')).toHaveText('Keine gültige Adresse: Die Endung fehlt. Beispiel: beispiel.ch');
    await expect(input).toHaveAttribute('aria-invalid', 'true');
    // The character counter appears before the 253 limit is hit.
    await input.fill(`${'a'.repeat(205)}.ch`);
    await expect(page.locator('.sites-add__count')).toHaveText('208 von 253 Zeichen');
    await input.fill('neu-hinzu.example.ch');
    await page.locator('.sites-add button[type="submit"]').click();
    await expect(page.locator('tr[data-host="neu-hinzu.example.ch"] .sites-badge--new')).toBeVisible();
    await expect(page.locator('.sites-limits')).toHaveText("Suche findet auch Subdomains. Höchstens 10'000 Websites, Adressen bis 253 Zeichen.");
    // Search: «3 von 1'249», reset.
    await page.locator('.sites-search__input').fill('bank');
    await expect(page.locator('.sites-count')).toHaveText("3 von 1'249");
    await expect(page.locator('.sites-table tbody tr')).toHaveCount(3);
    await page.locator('.sites-reset').click();
    await expect(page.locator('.sites-search__input')).toHaveValue('');
    // Dense: 200 rows first, then «Weitere 200 anzeigen».
    await expect(page.locator('.sites-table tbody tr')).toHaveCount(200);
    await page.locator('.sites-more').click();
    await expect(page.locator('.sites-table tbody tr')).toHaveCount(400);
    // Remove with «Rückgängig» (no confirm): the site comes back with its settings.
    await page.locator('.sites-search__input').fill('ebanking.raiffeisen');
    const row = page.locator('tr[data-host="ebanking.raiffeisen.ch"]');
    await row.locator('.sites-del').click();
    await expect(page.locator('dialog.dialog')).toHaveCount(0);
    await expect(row).toHaveCount(0);
    await expect(page.locator('.toast').last()).toContainText('«ebanking.raiffeisen.ch» entfernt');
    expect(Object.keys((await ext.send<{ sites: Record<string, unknown> }>({ type: 'sites:get' })).sites)).not.toContain('ebanking.raiffeisen.ch');
    await page.locator('.toast__action').last().click();
    await expect(row).toHaveCount(1);
    const back = (await ext.send<{ sites: Record<string, { mode?: string; enabled?: boolean }> }>({ type: 'sites:get' })).sites['ebanking.raiffeisen.ch'];
    expect(back).toEqual({ enabled: false, mode: 'aggressive' });
    // Long hosts are cut in the middle, the full host stays in the title.
    const longHost = `${[1, 2, 3, 4, 5].map((i) => `sehr-lange-subdomain-${i}`).join('.')}.kunden-service.example.ch`;
    await page.locator('.sites-search__input').fill('');
    await input.fill(longHost);
    await input.press('Enter');
    const name = page.locator(`tr[data-host="${longHost}"] .sites-host__name`);
    await expect(name).toHaveAttribute('title', longHost);
    await expect(name).toHaveAttribute('translate', 'no');
    expect((await name.innerText()).includes('…')).toBe(true);
    expect(await noOverflow(page)).toEqual([]);
    // Import (D04) previews three rows and counts skipped lines; focus returns to the button.
    const importBtn = page.locator('.db-head__actions .btn').first();
    await pickFile(page, () => importBtn.click(), 'sites.txt', 'import-a.example.ch\nimport-b.example.ch\nimport-c.example.ch\nimport-d.example.ch\nkein host\n');
    const dlg = page.locator('dialog.dialog');
    await expect(dlg.locator('.dialog__title')).toHaveText('4 Websites importieren?');
    await expect(dlg.locator('.dialog-list__row')).toHaveCount(4);
    await expect(dlg.locator('.dialog-list__row--foot')).toHaveText('+1 weitere - 1 Zeile ungültig, wird übersprungen');
    await dlg.locator('[data-dialog="cancel"]').click();
    await expect(dlg).toHaveCount(0);
    await expect(importBtn).toBeFocused();
    await pickFile(page, () => importBtn.click(), 'sites.txt', 'import-a.example.ch\n');
    await page.locator('dialog.dialog [data-dialog="confirm"]').click();
    await page.locator('.sites-search__input').fill('import-a');
    await expect(page.locator('tr[data-host="import-a.example.ch"]')).toHaveCount(1);
    // Empty state.
    await ext.send({ type: 'sites:set', sites: {} });
    await page.reload();
    await ready(page);
    await expect(page.locator('.tile-empty__title')).toHaveText('Noch keine Ausnahmen');
    await expect(page.locator('.db-head__actions .btn').nth(1)).toBeDisabled();
    expect(errors).toEqual([]);
    await page.close();
  });

  test('error banner «Erneut versuchen» loads the view again', async ({ ext }) => {
    for (const [view, type] of [
      ['privacy', 'config:get'],
      ['settings', 'config:get'],
      ['sites', 'sites:get'],
      ['filters', 'custom:get'],
    ] as const) {
      const { page } = await openPage(ext.context, { fail: { [type]: 1 } });
      await page.goto(`${ext.origin}/ui/dashboard.html#${view}`);
      const banner = page.locator('.db-error[role="alert"]');
      await expect(banner, `#${view} error`).toBeVisible();
      await expect(banner.locator('button')).toHaveText('Erneut versuchen');
      await banner.locator('button').click();
      await expect(banner, `#${view} retried`).toHaveCount(0);
      await expect(page.locator('.db-row, .cf-box, .sites-add').first(), `#${view} content`).toBeVisible();
      await page.close();
    }
  });

  test('Einstellungen: Verlauf löschen (D01), Alles zurücksetzen (D02 with checkbox and export), restore summary (D03)', async ({ ext }) => {
    await ext.send({ type: 'sites:set', sites: { 'keep.example.ch': { enabled: false } } });
    const { page, errors } = await openPage(ext.context);
    await page.goto(`${ext.origin}/ui/dashboard.html#settings`);
    await ready(page);
    const dlg = page.locator('dialog.dialog');

    // D01: outcome-named buttons, starts on «Verlauf behalten», Escape keeps, focus returns.
    const clear = page.getByRole('button', { name: 'Verlauf löschen…' });
    await clear.click();
    await expect(dlg.locator('.dialog__title')).toHaveText('Verlauf löschen?');
    await expect(dlg.locator('[data-dialog="confirm"]')).toHaveText('Verlauf löschen');
    await expect(dlg.locator('[data-dialog="cancel"]')).toHaveText('Verlauf behalten');
    expect(await page.evaluate(() => (document.activeElement as HTMLElement | null)?.dataset.dialog)).toBe('cancel');
    await page.keyboard.press('Escape');
    await expect(dlg).toHaveCount(0);
    await expect(clear).toBeFocused();
    await clear.click();
    await dlg.locator('[data-dialog="confirm"]').click();
    await expect(page.locator('.toast').last()).toContainText('Verlauf gelöscht');

    // D02: confirm needs the checkbox; the link really exports a backup.
    const reset = page.getByRole('button', { name: 'Alles zurücksetzen…' });
    await reset.click();
    const confirm = dlg.locator('[data-dialog="confirm"]');
    await expect(confirm).toBeDisabled();
    const [dl] = await Promise.all([page.waitForEvent('download'), dlg.getByRole('button', { name: 'Sicherung exportieren' }).click()]);
    expect(dl.suggestedFilename()).toMatch(/^bastion-shield-backup-.*\.json$/);
    await expect(dlg).toBeVisible();
    await dlg.locator('input[type="checkbox"]').check();
    await expect(confirm).toBeEnabled();
    await dlg.locator('[data-dialog="cancel"]').click();
    await expect(reset).toBeFocused();
    expect(Object.keys((await ext.send<{ sites: Record<string, unknown> }>({ type: 'sites:get' })).sites)).toContain('keep.example.ch');

    // D03: file name and summary before anything is replaced.
    const backup = {
      format: 'bastion-shield-backup',
      version: 1,
      exportedAt: '2026-10-14T10:00:00.000Z',
      settings: (await ext.send<{ settings: unknown }>({ type: 'config:get' })).settings,
      sites: { 'a.example.ch': { enabled: false }, 'b.example.ch': { enabled: false } },
      customFilters: '||x.example^\n||y.example^\n||z.example^',
    };
    const fileName = 'bastion-shield-sicherung-2026-10-14-mit-sehr-langem-namen.json';
    await pickFile(page, () => page.getByRole('button', { name: 'Sicherung importieren…' }).click(), fileName, JSON.stringify(backup));
    await expect(dlg.locator('.dialog__title')).toHaveText('Sicherung wiederherstellen?');
    await expect(dlg.locator('.set-file__name')).toHaveAttribute('title', fileName);
    await expect(dlg.locator('.set-file__meta')).toHaveText(/^Erstellt 14\.10\.2026, \d\d:\d\d - 2 Ausnahmen - 3 eigene Filter$/);
    await dlg.locator('[data-dialog="cancel"]').click();
    await expect(dlg).toHaveCount(0);

    // Narrow: the dialog becomes a sheet and nothing overflows.
    await page.setViewportSize({ width: 390, height: 800 });
    await reset.click();
    expect(await noOverflow(page)).toEqual([]);
    await page.keyboard.press('Escape');

    // Nerd mode on: protected domains report the left-out lines.
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: true, protectedDomains: [] } } }, 3000);
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.reload();
    await ready(page);
    await page.locator('.nerd-domains').fill('postfinance.ch\nmeine bank\nubs.com');
    await page.getByRole('button', { name: 'Domains speichern' }).click();
    await expect(page.locator('.nerd-domains__status')).toHaveText('2 Domains gespeichert. Nicht gültig und weggelassen: «meine bank» (Zeile 2).');
    await expect(page.locator('.nerd-domains__count')).toHaveText('2 von 200');
    await noRawKeys(page);
    expect(errors).toEqual([]);
    await page.close();
  });

  test('Entwicklertools: nerd mode off deep link, separators, readable reasons', async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: false } } }, 3000);
    const { page, errors } = await openPage(ext.context);
    await page.goto(`${ext.origin}/ui/dashboard.html#lab`);
    await ready(page);
    await expect(page.locator('.tile-empty__title')).toHaveText('Der Nerd-Modus ist aus');
    await page.getByRole('link', { name: 'Einstellungen öffnen' }).click();
    await expect(page.locator('body')).toHaveAttribute('data-view', 'settings');
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: true } } }, 3000);
    await page.goto(`${ext.origin}/ui/dashboard.html#lab`);
    await page.reload();
    await ready(page);
    await expect(page.locator('.lab-keys__sep').first()).toHaveText(' - ');
    await page.locator('.lab-play textarea').first().fill('||example.org^$documnet');
    await page.keyboard.press('Control+Enter');
    await expect(page.locator('.lab-res__err').first()).toContainText('Meinten Sie «document»?', { timeout: 15_000 });
    await noRawKeys(page);
    expect(errors).toEqual([]);
    await page.close();
  });

  test('Über: links are real, long licence names stay inside', async ({ ext }) => {
    const { page, errors } = await openPage(ext.context, { width: 390 });
    await page.goto(`${ext.origin}/ui/dashboard.html#about`);
    await ready(page);
    for (const href of await page.locator('a.ext-link').evaluateAll((as) => as.map((a) => (a as HTMLAnchorElement).href))) {
      expect.soft(href, 'external link').toMatch(/^(https:|mailto:)/);
    }
    expect(await noOverflow(page)).toEqual([]);
    expect(errors).toEqual([]);
    await page.close();
  });
});

test.describe('dashboard rule and system views: locked by the organisation', () => {
  let mx: ExtensionHarness;
  test.beforeAll(async ({ server }) => {
    test.setTimeout(90_000);
    mx = await ExtensionHarness.launch({ port: server.port, managedShim: true });
    expect((await mx.waitUntilReady(20_000)).ready).toBe(true);
    await mx.send({ type: 'settings:set', patch: { ui: { language: 'de' } } });
    await mx.send({ type: 'sites:set', sites: { 'eigene.example.ch': { enabled: false } } });
    const r = await setManagedPolicy(await mx.sw(), { lockSettings: true, disabledSites: ['firma-intranet.example.ch'], customFilters: ['||intranet-tracker.firma.example^'] });
    expect(r.patched).toBe(true);
    await poll(() => mx.send<{ managed: { lockSettings?: boolean } }>({ type: 'config:get' }), (c) => c.managed.lockSettings === true, 6000);
  });
  test.afterAll(async () => {
    await mx?.close();
  });

  test('locked rows show the lock and «Von Ihrer Organisation festgelegt»; editing is off', async () => {
    const { page, errors } = await openPage(mx.context);
    await page.goto(`${mx.origin}/ui/dashboard.html#privacy`);
    await ready(page);
    await expect(page.locator('.db-lock-notice')).toContainText('Von Ihrer Organisation verwaltet');
    expect(await page.locator('.db-row--locked .db-locked').count()).toBeGreaterThan(5);
    await expect(page.locator('.db-row--locked .db-locked').first()).toHaveText('Von Ihrer Organisation festgelegt');

    await page.goto(`${mx.origin}/ui/dashboard.html#settings`);
    await ready(page);
    await expect(page.getByRole('button', { name: 'Alles zurücksetzen…' })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Sicherung importieren…' })).toBeDisabled();

    await page.goto(`${mx.origin}/ui/dashboard.html#sites`);
    await ready(page);
    await expect(page.locator('.sites-add__input')).toBeDisabled();
    await expect(page.locator('tr[data-host="firma-intranet.example.ch"] .sites-badge--org')).toBeVisible();

    await page.goto(`${mx.origin}/ui/dashboard.html#filters`);
    await ready(page);
    await expect(page.locator('.notice--lock')).toContainText('Eigene Filter sind ausgeschaltet');
    await expect(page.locator('.cf-field')).toHaveAttribute('readonly', '');
    await expect(page.locator('.cf-box__title')).toHaveText('Editor - nur lesen');
    await expect(page.locator('.db-head__actions .btn').first()).toBeDisabled();
    await expect(page.locator('.cf-admin')).toContainText('intranet-tracker.firma.example');
    await noRawKeys(page);
    expect(errors).toEqual([]);
    await page.close();
  });
});
