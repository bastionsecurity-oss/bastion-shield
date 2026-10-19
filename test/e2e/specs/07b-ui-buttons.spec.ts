// Bastion Shield e2e — every control of the compact popup, the expanded popup
// (panel.html) and the dashboard tab does what it says: protection switch and
// reload hint, blocking mode, report dialog, «Cyber-Vorfall?» link and its
// settings switch (brand plate when off), expand / collapse, tab-only
// sections (↗), and every navigation entry renders without console errors.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ConsoleMessage, Page } from '@playwright/test';
import type { EffectiveConfig } from '../../../src/shared/types.ts';
import { expect, test } from '../support/fixtures.ts';
import { HOSTS, KNOWN_TRACKERS } from '../support/hosts.ts';
import { loadResources, poll } from '../support/pages.ts';

const INCIDENT = /^https:\/\/www\.bastionsecurity\.ch\/(kontakt|en\/contact)#vorfall$/;

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

/** The dashboard tab showing `hash` (openDashboard re-uses an open dashboard tab, so there may be no new page). */
async function dashboardTab(ext: { context: import('@playwright/test').BrowserContext }, hash: string): Promise<Page> {
  const re = new RegExp(`/ui/dashboard\.html#${hash}$`);
  const found = await poll(() => Promise.resolve(ext.context.pages().find((p) => re.test(p.url())) ?? null), (p) => p !== null, 6000, 100);
  if (!found) throw new Error(`no dashboard tab #${hash}; open: ${ext.context.pages().map((p) => p.url()).join(', ')}`);
  return found;
}

/** window.close() in a test tab would end the test early: neutralise it. */
async function keepOpen(page: Page): Promise<void> {
  await page.addInitScript(() => {
    (window as unknown as { __closed: number }).__closed = 0;
    window.close = () => {
      (window as unknown as { __closed: number }).__closed++;
    };
  });
}

test.describe('ui buttons', () => {
  test('compact popup, expanded popup and dashboard controls', async ({ page, server, ext }) => {
    // Start from defaults for the controls under test.
    await ext.sendAndApply({ type: 'settings:set', patch: { ui: { incidentCta: true, language: 'de' } } }, 3000);
    const specs = KNOWN_TRACKERS.slice(0, 4).map((t) => ({ url: server.url(t.host, t.path), kind: t.kind, label: t.host }));
    await loadResources(page, server, HOSTS.C, specs, { title: 'buttons' });
    const tabId = await ext.tabIdOf(page);
    expect(tabId).toBeGreaterThan(0);

    const popup = await ext.context.newPage();
    const errors = collectErrors(popup);
    await keepOpen(popup);
    // This test drives the plain page change (reduced motion); the morph has its own test below.
    await popup.emulateMedia({ reducedMotion: 'reduce' });
    await popup.goto(`${ext.origin}/ui/popup.html?tabId=${tabId}`);
    await expect(popup.locator('#pp-host')).toContainText(HOSTS.C);
    // German by default, whatever the browser language; every label is filled in.
    await expect(popup.locator('#pp-toggle-state')).toHaveText('Schutz ein');
    await expect(popup.locator('#pp-cta-slot a[data-cta="incident"]')).toHaveText('Cyber-Vorfall?');
    for (const sel of ['.pp-stat__label', '.pp-count__label']) {
      for (const txt of await popup.locator(sel).allInnerTexts()) expect.soft(txt.trim().length, `${sel} has text`).toBeGreaterThan(0);
    }

    // ---- Protection switch: off, reload hint, on again ----------------------
    const protect = popup.locator('#pp-protect');
    await expect(protect).toHaveAttribute('aria-checked', 'true');
    await protect.click();
    await expect(protect).toHaveAttribute('aria-checked', 'false');
    await expect(popup.locator('#pp-reload')).toBeVisible();
    const sitesOff = await ext.send<{ sites?: Record<string, { enabled?: boolean }> }>({ type: 'sites:get' });
    expect.soft(Object.values(sitesOff?.sites ?? {}).some((s) => s?.enabled === false), 'site saved as off').toBe(true);
    await popup.locator('#pp-reload-close').click();
    await expect(popup.locator('#pp-reload')).toBeHidden();
    await protect.click();
    await expect(protect).toHaveAttribute('aria-checked', 'true');

    // ---- Blocking mode -------------------------------------------------------
    const aggressive = popup.locator('#pp-mode-slot [data-value="aggressive"]');
    await aggressive.click();
    await expect(aggressive).toHaveAttribute('aria-checked', 'true');
    await popup.locator('#pp-mode-slot [data-value="standard"]').click();
    await expect(popup.locator('#pp-mode-slot [data-value="standard"]')).toHaveAttribute('aria-checked', 'true');

    // ---- Report dialog opens and cancels --------------------------------------
    if (await popup.locator('#pp-report').isVisible()) {
      await popup.locator('#pp-report').click();
      const dlg = popup.locator('dialog.dialog');
      await expect(dlg).toBeVisible();
      await dlg.locator('.btn--secondary').click();
      await expect(dlg).toHaveCount(0);
    }

    // ---- «Cyber-Vorfall?» opens the contact form in a new tab ----------------
    const cta = popup.locator('#pp-cta-slot a[data-cta="incident"]');
    await expect(cta).toBeVisible();
    await expect(cta).toHaveAttribute('href', INCIDENT);
    await expect(cta).toHaveAttribute('target', '_blank');
    const [ctaTab] = await Promise.all([ext.context.waitForEvent('page'), cta.click()]);
    expect.soft(ctaTab.url(), 'CTA tab').toMatch(/bastionsecurity\.ch/);
    await ctaTab.close();

    // ---- Expand to panel.html (Diese Website) --------------------------------
    await popup.locator('#pp-expand').click();
    await popup.waitForURL(/\/ui\/panel\.html\?tabId=\d+#site$/);
    await expect(popup.locator('h1.db-head__title')).toContainText(HOSTS.C);
    await expect(popup.locator('.site-tile')).toHaveCount(3);
    for (const txt of await popup.locator('.site-tile__label, .site-rules__summary .db-row__label, .db-row--action .db-row__label').allInnerTexts()) {
      expect.soft(txt.trim().length, 'site view label has text').toBeGreaterThan(0);
    }
    const viewport = await popup.evaluate(() => ({ w: document.body.offsetWidth, h: document.body.offsetHeight }));
    expect.soft(viewport, 'expanded popup size').toEqual({ w: 760, h: 560 });

    // Site switches and segmented controls in «Diese Website».
    const fpStrict = popup.locator('.db-view [role="radiogroup"] [data-value="strict"]').first();
    await fpStrict.click();
    await expect(fpStrict).toHaveAttribute('aria-checked', 'true');
    await expect(popup.locator('.site-reload')).toBeVisible();
    await popup.locator('.db-view [role="radiogroup"] [data-value="standard"]').nth(1).click();
    // Matched rules expand.
    await popup.locator('.site-rules > summary').click();
    await expect(popup.locator('.site-rules')).toHaveAttribute('open', '');

    // Every in-popup section renders.
    const sections = ['overview', 'activity', 'lists', 'sites', 'privacy', 'settings', 'about', 'site'];
    for (const s of sections) {
      await popup.locator(`.db-nav__link[data-view="${s}"]`).click();
      await expect(popup.locator('body')).toHaveAttribute('data-view', s);
      await expect(popup.locator('#db-view')).toHaveAttribute('aria-busy', 'false');
      const text = await popup.locator('#db-view').innerText();
      expect.soft(text.trim().length, `section ${s} renders`).toBeGreaterThan(10);
    }

    // Popup-only rules: no add form / import in Ausnahmen, «Bearbeiten» opens the tab.
    await popup.locator('.db-nav__link[data-view="sites"]').click();
    await expect(popup.locator('.sites-add')).toHaveCount(0);
    await popup.locator('[data-open-tab="sites"]').click();
    const sitesTab = await dashboardTab(ext, 'sites');
    await expect(sitesTab.locator('.sites-add')).toBeVisible();
    const closed = await poll(() => popup.evaluate(() => (window as unknown as { __closed: number }).__closed), (n) => n > 0, 3000, 50);
    expect.soft(closed, 'popup closes after opening the tab').toBeGreaterThan(0);

    // «Eigene Filter» (↗) never renders in the popup: it opens the dashboard tab.
    await popup.locator('.db-nav__link[data-view="filters"]').click();
    const filtersTab = await dashboardTab(ext, 'filters');
    await expect(filtersTab.locator('.cf-area')).toBeVisible();
    expect.soft(await popup.locator('body').getAttribute('data-view'), 'popup stays on its section').not.toBe('filters');

    // Settings: backup is tab-only, the CTA switch swaps CTA and brand plate.
    await popup.locator('.db-nav__link[data-view="settings"]').click();
    await expect(popup.locator('[data-open-tab="settings"]')).toBeVisible();
    await expect(popup.locator('.db-nav__foot a[data-cta="incident"]')).toBeVisible();
    const ctaRow = popup.locator('.db-row', { hasText: /Cyber/ });
    await ctaRow.locator('[role="switch"]').click();
    await poll(() => ext.send<EffectiveConfig>({ type: 'config:get' }), (c) => c?.settings?.ui?.incidentCta === false, 4000, 150);
    await expect(popup.locator('.db-nav__foot [data-cta="brand"]')).toBeVisible();
    await expect(popup.locator('.db-nav__foot [data-cta="brand"]')).toContainText('Bastion Shield');

    // Collapse back to the compact popup: brand plate instead of the CTA there too.
    await popup.locator('#db-collapse').click();
    await popup.waitForURL(/\/ui\/popup\.html\?tabId=\d+$/);
    await expect(popup.locator('#pp-cta-slot [data-cta="brand"]')).toBeVisible();
    await expect(popup.locator('#pp-cta-slot a[data-cta="incident"]')).toHaveCount(0);

    // Language: switch to English in Einstellungen, the page reloads in English.
    await ext.sendAndApply({ type: 'settings:set', patch: { ui: { incidentCta: true } } }, 3000);
    await popup.goto(`${ext.origin}/ui/panel.html?tabId=${tabId}#settings`);
    await expect(popup.locator('.db-nav__link[data-view="overview"]')).toContainText('Übersicht');
    await popup.locator('select[data-setting="ui.language"]').selectOption('en');
    await expect(popup.locator('.db-nav__link[data-view="overview"]')).toContainText('Overview', { timeout: 8000 });
    await popup.goto(`${ext.origin}/ui/popup.html?tabId=${tabId}`);
    await expect(popup.locator('#pp-toggle-state')).toHaveText('Protection on');

    // Restore.
    await ext.sendAndApply({ type: 'settings:set', patch: { ui: { incidentCta: true, language: 'de' } } }, 3000);
    expect(errors, 'console errors in popup and panel').toEqual([]);
    await popup.close();
  });

  test('gear morphs into the expanded view inside the popup and back', async ({ page, server, ext }) => {
    const specs = KNOWN_TRACKERS.slice(0, 3).map((t) => ({ url: server.url(t.host, t.path), kind: t.kind, label: t.host }));
    await loadResources(page, server, HOSTS.B, specs, { title: 'morph' });
    const tabId = await ext.tabIdOf(page);
    const popup = await ext.context.newPage();
    const errors = collectErrors(popup);
    await keepOpen(popup);
    await popup.emulateMedia({ reducedMotion: 'no-preference' });
    await popup.setViewportSize({ width: 760, height: 560 });
    await popup.goto(`${ext.origin}/ui/popup.html?tabId=${tabId}`);
    await expect(popup.locator('#pp-host')).toContainText(HOSTS.B);

    await popup.locator('#pp-expand').click();
    // The expanded view loads into an iframe in the same document (no navigation).
    await expect(popup.locator('#pp-panel.pp-panel--live')).toHaveCount(1);
    expect(popup.url(), 'no page change').toMatch(/\/ui\/popup\.html\?tabId=\d+$/);
    await expect(popup.locator('html')).toHaveClass(/pp-x/);
    // Paired elements are flying (both documents animate their half).
    const flying = await popup.evaluate(() => {
      const inner = (document.getElementById('pp-panel') as HTMLIFrameElement | null)?.contentDocument;
      return document.getAnimations().length + (inner?.getAnimations().length ?? 0);
    });
    expect.soft(flying, 'morph animations running').toBeGreaterThan(6);
    await expect(popup.locator('html')).toHaveClass(/pp-x-done/, { timeout: 3000 });
    const panel = popup.frameLocator('#pp-panel');
    await expect(panel.locator('h1.db-head__title')).toContainText(HOSTS.B);
    expect(await popup.evaluate(() => document.body.offsetWidth), 'document grew to 760').toBe(760);

    // Navigation inside the expanded view keeps working.
    await panel.locator('.db-nav__link[data-view="privacy"]').click();
    await expect(panel.locator('body')).toHaveAttribute('data-view', 'privacy');
    await panel.locator('.db-nav__link[data-view="site"]').click();

    // Collapse: back to the compact popup, iframe gone, 360 wide.
    await panel.locator('#db-collapse').click();
    await expect(popup.locator('#pp-panel')).toHaveCount(0, { timeout: 3000 });
    await expect(popup.locator('html')).not.toHaveClass(/pp-x/);
    expect(await popup.evaluate(() => document.body.offsetWidth), 'back to 360').toBe(360);
    await expect(popup.locator('#pp-protect')).toBeVisible();
    // And again: the morph can run repeatedly.
    await popup.locator('#pp-expand').click();
    await expect(popup.locator('html')).toHaveClass(/pp-x-done/, { timeout: 3000 });
    expect(errors, 'console errors during the morph').toEqual([]);
    await popup.close();
  });

  test('dashboard tab: CTA in the navigation, no «Diese Website», every section renders', async ({ ext }) => {
    const tab = await ext.context.newPage();
    const errors = collectErrors(tab);
    await tab.setViewportSize({ width: 1280, height: 860 });
    await tab.goto(`${ext.origin}/ui/dashboard.html#site`);
    // #site only exists in the popup: the tab falls back to the overview.
    await expect(tab.locator('body')).toHaveAttribute('data-view', 'overview');
    await expect(tab.locator('.db-nav__link[data-view="site"]')).toHaveCount(0);
    await expect(tab.locator('.db-nav__foot a[data-cta="incident"]')).toHaveAttribute('href', INCIDENT);
    await expect(tab.locator('.site-tile')).toHaveCount(3);
    for (const s of ['activity', 'lists', 'filters', 'sites', 'privacy', 'settings', 'about', 'overview']) {
      await tab.locator(`.db-nav__link[data-view="${s}"]`).click();
      await expect(tab.locator('body')).toHaveAttribute('data-view', s);
      await expect(tab.locator('#db-view')).toHaveAttribute('aria-busy', 'false');
    }
    // Tab-only controls are present in the tab.
    await tab.locator('.db-nav__link[data-view="sites"]').click();
    await expect(tab.locator('.sites-add')).toBeVisible();
    await tab.locator('.db-nav__link[data-view="settings"]').click();
    await expect(tab.locator('.set-actions .btn').first()).toBeVisible();
    expect(errors, 'dashboard console errors').toEqual([]);
    await tab.close();
  });
});
