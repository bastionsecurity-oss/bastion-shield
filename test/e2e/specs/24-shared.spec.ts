// Bastion Shield e2e — shared UI of the optimised design: command palette
// (K01–K03) and the welcome page (W01–W03). Every control does what its
// label says, keyboard paths work, light and dark, narrow, long input, no
// raw i18n keys and no failed extension requests.
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

/** Visible text that looks like an untranslated message key (camelCase with a known prefix). */
async function rawKeys(page: Page): Promise<string[]> {
  const text = await page.locator('body').innerText();
  return text.match(/\b(cmdk|welcome|nav|set|priv|sites|lists|myLists|act|cf|popup|report|notice|blocked|bounce|action|toast)[A-Z][A-Za-z]+\b/g) ?? [];
}

/** True when nothing inside `sel` is wider than the viewport. */
async function noHorizontalOverflow(page: Page): Promise<boolean> {
  return page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
}

/** SCREENS=<dir> saves screenshots for the design comparison. */
async function shot(page: Page, name: string): Promise<void> {
  if (!process.env.SCREENS) return;
  await page.waitForTimeout(400); // let open animations settle
  await page.screenshot({ path: `${process.env.SCREENS}/${name}.png` });
}

async function openDashboard(page: Page, origin: string, hash: string): Promise<void> {
  await page.goto(`${origin}/ui/dashboard.html#${hash}`, { waitUntil: 'load' });
  await page.waitForFunction(() => document.body.dataset.view !== '', null, { timeout: 8000 });
  await page.waitForTimeout(300);
}

test.describe('command palette (K01–K03)', () => {
  test.beforeEach(async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { ui: { language: 'de' } } }, 3000);
  });

  test('opens with Ctrl+K and the search button, groups hits, bold match, Enter navigates', async ({ ext }) => {
    const page = await ext.context.newPage();
    const errors = collectErrors(page);
    await openDashboard(page, ext.origin, 'overview');

    await page.keyboard.press('Control+k');
    const dlg = page.locator('dialog.cmdk[open]');
    await expect(dlg).toBeVisible();
    const input = dlg.locator('.cmdk__input');
    await expect(input).toBeFocused();
    await expect(input).toHaveAttribute('maxlength', '200');

    await input.fill('filter');
    const groups = await dlg.locator('.cmdk__group').allInnerTexts();
    expect(groups.length).toBeGreaterThan(0);
    expect(new Set(groups).size, 'each group appears once').toBe(groups.length);
    // Match highlight: bold, not coloured.
    const mark = dlg.locator('.cmdk__label mark').first();
    await expect(mark).toBeVisible();
    const style = await mark.evaluate((m) => {
      const cs = getComputedStyle(m);
      const parent = getComputedStyle(m.parentElement!);
      return { weight: Number(cs.fontWeight), color: cs.color, parentColor: parent.color, bg: cs.backgroundColor };
    });
    expect(style.weight).toBeGreaterThanOrEqual(600);
    expect(style.color).toBe(style.parentColor);
    expect(style.bg).toBe('rgba(0, 0, 0, 0)');
    // The «Filterlisten» section has its count on the right.
    const listsRow = dlg.locator('.cmdk__opt--views', { hasText: 'Filterlisten' }).first();
    await expect(listsRow.locator('.cmdk__hint')).toHaveText(/\d+ Listen aktiv/);
    await shot(page, 'palette-K01');

    // Arrow keys move, Enter opens the active row.
    await input.fill('Datenschutz');
    await expect(dlg.locator('.cmdk__opt[aria-selected="true"]')).toContainText('Datenschutz');
    await page.keyboard.press('Enter');
    await expect(dlg).toHaveCount(0);
    await expect(page).toHaveURL(/#privacy$/);

    // The search button in the navigation opens it too; Esc closes it.
    await page.locator('[data-cmdk]').first().click();
    await expect(page.locator('dialog.cmdk[open]')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator('dialog.cmdk[open]')).toHaveCount(0);

    expect(await rawKeys(page)).toEqual([]);
    expect(errors).toEqual([]);
    await page.close();
  });

  test('empty state suggests three sections that navigate (K02)', async ({ ext }) => {
    const page = await ext.context.newPage();
    const errors = collectErrors(page);
    await openDashboard(page, ext.origin, 'overview');
    await page.keyboard.press('Control+k');
    const dlg = page.locator('dialog.cmdk[open]');
    await dlg.locator('.cmdk__input').fill('xyzqq');
    await expect(dlg.locator('.cmdk__empty')).toBeVisible();
    await expect(dlg.locator('.cmdk__empty-title')).toHaveText('Nichts gefunden für «xyzqq»');
    await expect(dlg.locator('.cmdk__list')).toBeHidden();
    const chips = dlg.locator('.cmdk__suggest button');
    await expect(chips).toHaveText(['Filterlisten', 'Website-Ausnahmen', 'Einstellungen']);
    await shot(page, 'palette-K02');
    // Keyboard: Tab leaves the field for the first suggestion.
    await page.keyboard.press('Tab');
    await expect(chips.first()).toBeFocused();
    await page.keyboard.press('Tab');
    await page.keyboard.press('Enter');
    await expect(page.locator('dialog.cmdk[open]')).toHaveCount(0);
    await expect(page).toHaveURL(/#sites$/);
    expect(errors).toEqual([]);
    await page.close();
  });

  test('long query and long hits stay inside the palette (K03), light and dark', async ({ ext }) => {
    const long = 'portal.kunden-service-sparkasse-mittelland-emmental-region-bern.ch';
    await ext.sendAndApply({ type: 'sites:set', sites: { [long]: { enabled: false } } }, 3000).catch(() => undefined);
    for (const scheme of ['light', 'dark'] as const) {
      const page = await ext.context.newPage();
      await page.emulateMedia({ colorScheme: scheme });
      await page.setViewportSize({ width: 800, height: 700 });
      const errors = collectErrors(page);
      await openDashboard(page, ext.origin, 'overview');
      await page.keyboard.press('Control+k');
      const dlg = page.locator('dialog.cmdk[open]');
      await dlg.locator('.cmdk__input').fill('sparkasse-mittelland-emmental');
      const host = dlg.locator('.cmdk__label--host').first();
      await shot(page, `palette-K03-${scheme}`);
      if (await host.count()) {
        await expect(host).toHaveAttribute('translate', 'no');
        await expect(host).toHaveAttribute('title', long);
        expect((await host.innerText()).length).toBeLessThan(long.length);
        expect(await host.evaluate((el) => el.scrollWidth <= el.clientWidth + 1)).toBe(true);
      }
      await dlg.locator('.cmdk__input').fill('x'.repeat(250));
      expect((await dlg.locator('.cmdk__input').inputValue()).length).toBe(200);
      const box = await dlg.boundingBox();
      expect(box!.width).toBeLessThanOrEqual(600);
      expect(await noHorizontalOverflow(page)).toBe(true);
      expect(errors).toEqual([]);
      await page.close();
    }
    await ext.sendAndApply({ type: 'sites:set', sites: {} }, 3000).catch(() => undefined);
  });
});

test.describe('welcome (W01–W03)', () => {
  for (const [label, width, scheme] of [
    ['W01 light', 1280, 'light'],
    ['W02 dark', 1280, 'dark'],
    ['W03 narrow', 390, 'light'],
  ] as const) {
    test(`${label}: points, pin tip and both buttons work`, async ({ ext }) => {
      await ext.sendAndApply({ type: 'settings:set', patch: { ui: { language: 'de' } } }, 3000);
      const page = await ext.context.newPage();
      await page.emulateMedia({ colorScheme: scheme });
      await page.setViewportSize({ width, height: 900 });
      const errors = collectErrors(page);
      await openDashboard(page, ext.origin, 'welcome');
      await expect(page.locator('.welcome__title')).toHaveText('Willkommen bei Bastion Shield');
      await expect(page.locator('.welcome__title [translate="no"]')).toHaveText('Bastion Shield');
      await expect(page.locator('.welcome__points li')).toHaveCount(3);
      await expect(page.locator('.welcome__points .tile[aria-hidden="true"]')).toHaveCount(3);
      await expect(page.locator('.welcome__lead')).toHaveText('Ihr Browser ist ab jetzt geschützt. Einrichten müssen Sie nichts.');
      expect(await noHorizontalOverflow(page)).toBe(true);
      await shot(page, `welcome-${label.split(' ')[0]}-${scheme}`);
      // Primary first, then the outlined secondary.
      const buttons = page.locator('.welcome__actions .btn');
      await expect(buttons).toHaveText(['Übersicht öffnen', 'Filterlisten ansehen']);
      if (width < 480) {
        const [a, b] = [await buttons.nth(0).boundingBox(), await buttons.nth(1).boundingBox()];
        expect(a!.width).toBeGreaterThan(300);
        expect(b!.y).toBeGreaterThan(a!.y);
      }
      expect(await rawKeys(page)).toEqual([]);
      await buttons.nth(1).click();
      await expect(page).toHaveURL(/#lists$/);
      await openDashboard(page, ext.origin, 'welcome');
      await page.locator('.welcome__actions .btn').first().focus();
      await page.keyboard.press('Enter');
      await expect(page).toHaveURL(/#overview$/);
      expect(errors).toEqual([]);
      await page.close();
    });
  }
});
