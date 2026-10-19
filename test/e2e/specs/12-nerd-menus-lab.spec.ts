// Bastion Shield e2e — nerd-mode context menu and Lab deep links in a real
// Chromium. Playwright cannot open a native context menu, so the menu items
// are checked through the service worker (contextMenus.update fails for an
// id that does not exist) and the Lab is opened with the URLs the click
// handler builds (unit-tested in test/background/nerd-menus.test.ts).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { Page } from '@playwright/test';
import { expect, test } from '../support/fixtures.ts';
import { poll } from '../support/pages.ts';

const IDS = ['nerd-root', 'nerd-explain-url', 'nerd-test-selection', 'nerd-blame-selection', 'nerd-bisect', 'nerd-open-lab'];

test.describe('nerd mode menus and Lab', () => {
  test.afterAll(async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: false } } }, 6000);
  });

  test('context menu items exist only while nerd mode is on', async ({ ext }) => {
    const present = async (): Promise<string[]> =>
      (await ext.sw()).evaluate(async (ids: string[]) => {
        const out: string[] = [];
        for (const id of ids) {
          const ok = await new Promise<boolean>((res) => chrome.contextMenus.update(id, {}, () => res(!chrome.runtime.lastError)));
          if (ok) out.push(id);
        }
        return out;
      }, IDS);
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: true } } }, 6000);
    expect(await poll(present, (v) => v.length === IDS.length, 5000)).toEqual(IDS);
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: false } } }, 6000);
    expect(await poll(present, (v) => v.length === 0, 5000)).toEqual([]);
  });

  test('Lab deep links prefill and run; keyboard shortcuts', async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: true } } }, 6000);
    const page: Page = await ext.context.newPage();
    try {
      const dash = `chrome-extension://${ext.id}/ui/dashboard.html`;
      const target = 'https://ads.example.invalid/pixel.gif';
      await page.goto(`${dash}#lab?url=${encodeURIComponent(target)}&site=news.example.invalid&type=image`);
      await expect(page.locator('.lab-play textarea').nth(1)).toHaveValue(`${target} image news.example.invalid`);
      // The installed rules are scanned and every probe gets a verdict.
      await expect(page.locator('.lab-x__verdict')).toHaveCount(1, { timeout: 20_000 });

      await page.goto(`${dash}#lab/blame?filter=${encodeURIComponent('||doubleclick.net^')}`);
      await page.reload();
      await expect(page.locator('.lab-blame__input')).toHaveValue('||doubleclick.net^');

      // Same view, new hash: the Lab follows it without a reload.
      await page.evaluate(() => (location.hash = `#lab?filter=${encodeURIComponent('||example.invalid^')}`));
      await expect(page.locator('.lab-play textarea').first()).toHaveValue('||example.invalid^');
      await expect(page.locator('.lab-res')).toHaveCount(1);

      await page.locator('body').click({ position: { x: 5, y: 5 } });
      await page.keyboard.press('/');
      expect(await page.evaluate(() => document.activeElement === document.querySelector('.lab-play textarea'))).toBe(true);
      await page.keyboard.press('Escape');
      expect(await page.evaluate(() => document.activeElement?.tagName)).toBe('BODY');
    } finally {
      await page.close();
    }
  });
});
