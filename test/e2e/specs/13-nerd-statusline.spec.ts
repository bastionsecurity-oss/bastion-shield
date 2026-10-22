// Bastion Shield e2e — nerd mode popup statusline in a real Chromium: the
// statusline row, the command line (Ctrl+K, fuzzy match, Enter), the
// keyboard-driven filter bisect with its toolbar badge step, and switching
// nerd mode off ending a running bisect (rules gone, badge handed back).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { Page } from '@playwright/test';
import { RULE_ID } from '../../../src/shared/constants.ts';
import type { BisectView } from '../../../src/shared/types.ts';
import { expect, test } from '../support/fixtures.ts';
import { HOSTS, KNOWN_TRACKERS } from '../support/hosts.ts';
import { loadResources, poll } from '../support/pages.ts';

const isBisectRule = (id: number): boolean => id >= RULE_ID.SESSION_BISECT_START && id <= RULE_ID.SESSION_BISECT_END;

async function openPopup(ext: { context: { newPage(): Promise<Page> }; origin: string }, tabId: number): Promise<Page> {
  const popup = await ext.context.newPage();
  await popup.goto(`${ext.origin}/ui/popup.html?tabId=${tabId}`);
  return popup;
}

test.describe('nerd statusline', () => {
  test.beforeAll(async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: true } } }, 6000);
  });
  test.afterAll(async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: false } } }, 6000);
  });

  test('statusline, command line, keyboard bisect with badge step, nerd off ends the bisect', async ({ page, server, ext }) => {
    const specs = KNOWN_TRACKERS.map((t) => ({ url: server.url(t.host, t.path), kind: t.kind, label: t.host }));
    const rs = await loadResources(page, server, HOSTS.A, specs, { title: 'nerd statusline' });
    expect(rs.filter((r) => r.blocked).length, 'some requests were blocked').toBeGreaterThan(1);
    const tabId = await ext.tabIdOf(page);
    const sw = await ext.sw();
    const badge = () => sw.evaluate((id: number) => chrome.action.getBadgeText({ tabId: id }), tabId);
    const bisectRules = async () => (await sw.evaluate(() => chrome.declarativeNetRequest.getSessionRules())).filter((r) => isBisectRule(r.id)).length;

    const popup = await openPopup(ext, tabId);
    const sl = popup.locator('#pp-nerd');
    await expect(sl).toBeVisible();
    await expect(sl).toContainText(/\d+ hosts?/i, { timeout: 5000 });
    await expect(sl.locator('kbd').first()).toContainText(/k/i);

    // Command line: Ctrl+K, fuzzy "bis", Enter starts the bisect.
    await popup.keyboard.press('Control+K');
    const input = sl.locator('input');
    await expect(input).toBeFocused();
    await input.pressSequentially('bis');
    await expect(sl.locator('[role="option"][aria-selected="true"]')).toContainText('bisect');
    await input.press('Enter');
    await expect(sl).toContainText(/bisect 1\/(≤)?\d+/i, { timeout: 8000 });
    const view = (await ext.send<{ bisect: BisectView }>({ type: 'nerd:bisect', action: 'state', tabId })).bisect;
    expect(view.phase).toBe('testing');
    expect(await bisectRules(), 'test rules installed').toBeGreaterThan(0);
    // The badge shows the step (also after the test reload reset it).
    await poll(badge, (t) => t === `1/${view.maxSteps}`, 6000, 200);
    expect(await badge()).toBe(`1/${view.maxSteps}`);

    // "y": the page works with everything let through -> step 2.
    await popup.locator('body').press('y');
    await expect(sl).toContainText(/bisect 2\//i, { timeout: 8000 });
    await poll(badge, (t) => t.startsWith('2/'), 6000, 200);

    // Esc aborts: rules removed, badge handed back.
    await popup.locator('body').press('Escape');
    await expect(sl).not.toContainText('bisect', { timeout: 8000 });
    expect(await bisectRules(), 'rules removed on abort').toBe(0);
    await poll(badge, (t) => !t.includes('/'), 6000, 200);
    expect(await badge()).not.toContain('/');

    // Nerd mode off while a bisect runs: everything ends without a reload.
    await ext.send({ type: 'nerd:bisect', action: 'start', tabId });
    expect(await bisectRules()).toBeGreaterThan(0);
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: false } } }, 6000);
    await poll(bisectRules, (n) => n === 0, 6000, 200);
    expect(await bisectRules(), 'nerd off removes the bisect rules').toBe(0);
    await poll(badge, (t) => !t.includes('/'), 6000, 200);
    await ext.sendAndApply({ type: 'settings:set', patch: { nerd: { enabled: true } } }, 6000);
    await popup.close();
  });
});
