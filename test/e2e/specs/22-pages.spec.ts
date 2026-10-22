// Bastion Shield e2e — extension pages of the «UI Optimised» redesign
// (phase 2, artboards S01–S10): the strict-block interstitial and the
// bounce page. Every control does what its label says, the keyboard path
// works, light / dark / 390px / very long hosts render without overflow, and
// no raw i18n key, middle dot or failed extension request shows up.
//
// BASTION_SHOTS=<dir> also writes the screenshots compared with the artboards.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { mkdirSync } from 'node:fs';
import path from 'node:path';
import type { Page } from '@playwright/test';
import { expect, test } from '../support/fixtures.ts';
import type { FixtureServer } from '../support/server.ts';
import { HOSTS } from '../support/hosts.ts';
import { pickStrictHosts } from '../support/pickers.ts';

const SHOTS = process.env.BASTION_SHOTS;
const RAW_KEY = /\b(?:blocked|bounce|action)[A-Z][A-Za-z]+\b/;

/** Collects failed chrome-extension:// requests and page errors for one page. */
function watch(page: Page): { failed: string[]; errors: string[] } {
  const out = { failed: [] as string[], errors: [] as string[] };
  page.on('requestfailed', (r) => r.url().startsWith('chrome-extension://') && out.failed.push(`${r.url()} ${r.failure()?.errorText ?? ''}`));
  page.on('response', (r) => r.url().startsWith('chrome-extension://') && r.status() >= 400 && out.failed.push(`${r.url()} ${r.status()}`));
  page.on('pageerror', (e) => out.errors.push(String(e)));
  return out;
}

async function openBlocked(page: Page, server: FixtureServer, host: string, p = '/landing/index.html?campaign=e2e'): Promise<string> {
  const url = server.url(host, p);
  await page.goto(url).catch(() => {});
  await page.waitForURL(/\/pages\/blocked\.html/, { timeout: 10_000 });
  await page.waitForFunction(() => document.body.dataset.state === 'ready');
  return url;
}

/** Checks every state of both pages shares. */
async function commonChecks(page: Page, label: string): Promise<void> {
  const r = await page.evaluate(() => ({
    text: document.body.innerText,
    themes: Array.from(document.querySelectorAll('meta[name="theme-color"]')).map((m) => `${m.getAttribute('media')}|${m.getAttribute('content')}`),
    scheme: document.querySelector('meta[name="color-scheme"]')?.getAttribute('content') ?? '',
    overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
  }));
  expect.soft(r.text, `${label}: no raw i18n key`).not.toMatch(RAW_KEY);
  expect.soft(r.text, `${label}: no middle dot`).not.toContain('·');
  expect.soft(r.text, `${label}: no three-dot ellipsis`).not.toContain('...');
  expect.soft(r.themes.some((x) => x.includes('light')) && r.themes.some((x) => x.includes('dark')), `${label}: theme-color for light and dark (${r.themes.join(', ')})`).toBe(true);
  expect.soft(r.scheme, `${label}: color-scheme`).toBe('light dark');
  expect.soft(r.overflow, `${label}: no horizontal overflow`).toBeLessThanOrEqual(0);
}

async function focusedId(page: Page): Promise<string> {
  return page.evaluate(() => document.activeElement?.id ?? '');
}

async function shot(page: Page, name: string): Promise<void> {
  if (!SHOTS) return;
  mkdirSync(SHOTS, { recursive: true });
  await page.waitForTimeout(250);
  await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: true });
}

test.describe('strict-block page (S01–S07)', () => {
  test.beforeEach(async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { ui: { language: 'de' } } }, 3000);
  });

  test('S01/S02: copy, controls, confirm bar and proceed', async ({ page, server, dist }) => {
    const pick = pickStrictHosts(dist, ['urlhaus', 'ublock-badware'], 1)[0];
    expect(pick, 'a strict-block rule exists in a security list').toBeTruthy();
    const w = watch(page);
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' });
    const url = await openBlocked(page, server, pick.host);

    const category = dist.list(pick.listId)?.category;
    if (category === 'security') await expect(page.locator('#bl-title')).toHaveText('Gefährliche Seite blockiert');
    await expect(page.locator('.bl-tile')).toHaveAttribute('aria-hidden', 'true');
    const chip = page.locator('#bl-host');
    await expect(chip).toHaveText(pick.host);
    await expect(chip).toHaveAttribute('translate', 'no');
    await expect(chip).toHaveAttribute('title', pick.host);
    await expect(page.locator('.bl-foot span[translate="no"]')).toHaveText('Bastion Shield');
    await expect(page.locator('#bl-foot')).toHaveText('Bastion Shield prüft lokal. Es werden keine Daten gesendet.');
    await commonChecks(page, 'S01');
    await shot(page, 'S01-light');
    await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
    await expect.poll(() => page.evaluate(() => getComputedStyle(document.body).backgroundColor), { message: 'dark background' }).toBe('rgb(23, 28, 30)');
    await shot(page, 'S05-dark');
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' });

    // Details: a disclosure with reason, list and the full URL.
    const toggle = page.locator('#bl-details-toggle');
    await expect(toggle).toHaveText('Details');
    await expect(toggle).toHaveAttribute('aria-expanded', 'false');
    await expect(page.locator('#bl-details')).toBeHidden();
    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-expanded', 'true');
    await expect(page.locator('#bl-details')).toBeVisible();
    await expect(page.locator('#bl-url')).toHaveText(url);
    await expect(page.locator('#bl-category')).not.toHaveText('–');
    await expect(page.locator('#bl-list')).not.toHaveText('–');

    // «Trotzdem öffnen…» opens the confirm bar; focus starts on «Abbrechen».
    const proceed = page.locator('#bl-proceed');
    await expect(proceed).toHaveText('Trotzdem öffnen…');
    await proceed.click();
    const bar = page.locator('#bl-confirm');
    await expect(bar).toBeVisible();
    await expect(proceed).toHaveAttribute('aria-expanded', 'true');
    await expect(page.locator('#bl-confirm-title')).toHaveText('Nur in diesem Tab öffnen?');
    expect(await focusedId(page), 'focus on «Abbrechen»').toBe('bl-confirm-cancel');
    await expect(page.locator('#bl-confirm-go')).toHaveText('Seite öffnen');
    await expect(page.locator('#bl-confirm-go')).toHaveClass(/btn--danger/);
    await commonChecks(page, 'S02');
    await shot(page, 'S02-light');
    await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
    await shot(page, 'S02-dark');
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' });

    // «Abbrechen» closes and returns focus to «Trotzdem öffnen…».
    await page.locator('#bl-confirm-cancel').click();
    await expect(bar).toBeHidden();
    await expect(proceed).toHaveAttribute('aria-expanded', 'false');
    expect(await focusedId(page), 'focus back on «Trotzdem öffnen…»').toBe('bl-proceed');
    // Esc does the same.
    await proceed.click();
    await expect(bar).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(bar).toBeHidden();
    expect(await focusedId(page), 'Esc returns focus to «Trotzdem öffnen…»').toBe('bl-proceed');
    // Details closes again.
    await toggle.click();
    await expect(page.locator('#bl-details')).toBeHidden();

    // «Seite öffnen» proceeds to the blocked URL.
    await proceed.click();
    await page.locator('#bl-confirm-go').click();
    await page.waitForURL((u) => u.hostname === pick.host, { timeout: 10_000 });
    expect(new URL(page.url()).hostname).toBe(pick.host);
    expect.soft(w.failed, 'no failed extension requests').toEqual([]);
    expect.soft(w.errors, 'no page errors').toEqual([]);
  });

  test('S07: a failed exception shows the error row and «Erneut versuchen» retries', async ({ page, server, dist }) => {
    const pick = pickStrictHosts(dist, ['urlhaus', 'ublock-badware'], 3)[2] ?? pickStrictHosts(dist, ['urlhaus'], 1)[0];
    const w = watch(page);
    await page.setViewportSize({ width: 1280, height: 800 });
    await openBlocked(page, server, pick.host);
    // The next blocked:proceed fails (the service worker does not answer), later ones go through.
    await page.evaluate(() => {
      const rt = chrome.runtime as unknown as { sendMessage: (m: unknown) => Promise<unknown> };
      const orig = rt.sendMessage.bind(rt);
      let failures = 1;
      (window as unknown as { __proceedCalls: number }).__proceedCalls = 0;
      rt.sendMessage = (m: unknown) => {
        if ((m as { type?: string }).type === 'blocked:proceed') {
          (window as unknown as { __proceedCalls: number }).__proceedCalls++;
          if (failures-- > 0) return new Promise((_, reject) => setTimeout(() => reject(new Error('simulated')), 200));
        }
        return orig(m);
      };
    });
    await page.locator('#bl-proceed').click();
    await page.locator('#bl-confirm-go').click();
    const err = page.locator('#bl-error');
    await expect(err).toBeVisible();
    await expect(err).toHaveAttribute('role', 'alert');
    await expect(err).toContainText('Ausnahme nicht eingerichtet');
    await expect(page.locator('#bl-confirm')).toBeHidden();
    expect(await focusedId(page), 'focus moves to «Erneut versuchen»').toBe('bl-retry');
    await expect(page.locator('#bl-retry')).toHaveText('Erneut versuchen');
    await commonChecks(page, 'S07');
    await shot(page, 'S07-light');
    await page.locator('#bl-retry').click();
    await page.waitForURL((u) => u.hostname === pick.host, { timeout: 10_000 });
    expect(new URL(page.url()).hostname, 'retry set up the exception and opened the page').toBe(pick.host);
    expect.soft(w.failed).toEqual([]);
    expect.soft(w.errors).toEqual([]);
  });

  test('keyboard only: back, proceed, cancel, details', async ({ page, server, dist }) => {
    const pick = pickStrictHosts(dist, ['urlhaus', 'ublock-badware'], 2)[1] ?? pickStrictHosts(dist, ['urlhaus'], 1)[0];
    const start = server.setPage(HOSTS.A, '/e2e/pages-start.html', '<!doctype html><meta charset="utf-8"><title>start</title><p>start');
    await page.goto(start);
    await openBlocked(page, server, pick.host);
    await page.keyboard.press('Tab');
    expect(await focusedId(page), 'first Tab stop is «Zurück»').toBe('bl-back');
    await page.keyboard.press('Tab');
    expect(await focusedId(page)).toBe('bl-proceed');
    const ring = await page.evaluate(() => {
      const s = getComputedStyle(document.activeElement!);
      return `${s.outlineStyle} ${s.outlineWidth} ${s.outlineOffset}`;
    });
    expect(ring, 'focus is visible (2px, 2px offset)').toBe('solid 2px 2px');
    await page.keyboard.press('Enter');
    expect(await focusedId(page)).toBe('bl-confirm-cancel');
    await page.keyboard.press('Tab');
    expect(await focusedId(page)).toBe('bl-confirm-go');
    await page.keyboard.press('Shift+Tab');
    await page.keyboard.press('Enter');
    await expect(page.locator('#bl-confirm')).toBeHidden();
    expect(await focusedId(page)).toBe('bl-proceed');
    await page.keyboard.press('Tab');
    expect(await focusedId(page)).toBe('bl-details-toggle');
    await page.keyboard.press('Enter');
    await expect(page.locator('#bl-details-toggle')).toHaveAttribute('aria-expanded', 'true');
    await page.keyboard.press('Space');
    await expect(page.locator('#bl-details-toggle')).toHaveAttribute('aria-expanded', 'false');
    await page.keyboard.press('Shift+Tab');
    await page.keyboard.press('Shift+Tab');
    expect(await focusedId(page)).toBe('bl-back');
    await page.keyboard.press('Enter');
    await page.waitForURL(start, { timeout: 5000 });
    expect(page.url(), '«Zurück» returns to the page before the block').toBe(start);
  });

  test('«Zurück» works in a tab without history', async ({ page, server, dist, ext }) => {
    const pick = pickStrictHosts(dist, ['urlhaus', 'ublock-badware'], 1)[0];
    void page;
    // A tab opened straight onto the blocked address (as from a link in a new tab).
    const tabPage = ext.context.waitForEvent('page');
    await ext.api((u: string) => chrome.tabs.create({ url: u }), server.url(pick.host, '/landing/fresh.html'));
    const p = await tabPage;
    await p.waitForURL(/\/pages\/blocked\.html/, { timeout: 10_000 });
    await p.waitForFunction(() => document.body.dataset.state === 'ready');
    expect(await p.evaluate(() => history.length), 'the blocked page is the only history entry').toBe(1);
    await p.locator('#bl-back').click();
    await p.waitForURL((u) => !u.href.includes('/pages/blocked.html'), { timeout: 5000 });
    expect(p.url(), '«Zurück» leaves the blocked page').not.toContain('/pages/blocked.html');
    await p.close();
  });

  test('S04/S06: very long host and URL, 390px, dark', async ({ page, server, dist }) => {
    const pick = pickStrictHosts(dist, ['urlhaus', 'ublock-badware'], 1)[0];
    const w = watch(page);
    const longHost = `secure-login-ubs-ch-verify-kundenportal-session-7731-2208-4410.authentification-service-check-sicherheit.${pick.host}`;
    const longPath = `/login/e-banking/?ref=mail&session=${'8f2c91aa04b7c3e1d9'.repeat(6)}`;
    for (const [width, height] of [
      [1280, 900],
      [390, 844],
    ] as const) {
      await page.setViewportSize({ width, height });
      for (const scheme of ['light', 'dark'] as const) {
        await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
        const url = await openBlocked(page, server, longHost, longPath);
        const chip = page.locator('#bl-host');
        await expect(chip).toHaveAttribute('title', longHost);
        const box = await chip.evaluate((el) => {
          const lh = parseFloat(getComputedStyle(el).lineHeight);
          const pad = parseFloat(getComputedStyle(el).paddingTop) + parseFloat(getComputedStyle(el).paddingBottom);
          return { lines: Math.round((el.getBoundingClientRect().height - pad) / lh), text: el.textContent ?? '' };
        });
        expect(box.lines, `${width}px ${scheme}: host chip at most two lines`).toBeLessThanOrEqual(2);
        expect(box.text, `${width}px ${scheme}: long host is cut in the middle`).toContain('…');
        expect(box.text.endsWith(pick.host.split('.').slice(-2).join('.')), 'TLD kept').toBe(true);
        await page.locator('#bl-details-toggle').click();
        await expect(page.locator('#bl-url')).toHaveText(url);
        await commonChecks(page, `long ${width}px ${scheme}`);
        if (width === 390) {
          const widths = await page.evaluate(() => [document.getElementById('bl-back')!.getBoundingClientRect().width, document.querySelector('.bl-main')!.getBoundingClientRect().width]);
          expect(widths[0], '390px: «Zurück» spans the column').toBeCloseTo(widths[1], 0);
        }
        await shot(page, `S04-long-${width}-${scheme}`);
        // The plain host at this width (S06).
        if (width === 390) {
          await openBlocked(page, server, pick.host);
          await commonChecks(page, `S06 ${scheme}`);
          await shot(page, `S06-${scheme}`);
        }
      }
    }
    expect.soft(w.failed).toEqual([]);
    expect.soft(w.errors).toEqual([]);
  });

  test('S03: tracker variant (when a tracking list strict-blocks a host)', async ({ page, server, dist }) => {
    const picks = pickStrictHosts(dist, ['easylist', 'easyprivacy', 'ublock', 'ublock-privacy'], 40);
    const pick = picks.find((p) => ['ads', 'privacy', 'regional'].includes(dist.list(p.listId)?.category ?? ''));
    test.skip(!pick, 'no strict-block rule in an ads / privacy list in this build');
    await page.setViewportSize({ width: 1280, height: 800 });
    await openBlocked(page, server, pick!.host);
    await expect(page.locator('#bl-title')).toHaveText('Tracker-Seite blockiert');
    await expect(page.locator('#bl-text')).toContainText('sammelt Daten für Werbung.');
    await expect(page.locator('body')).toHaveAttribute('data-kind', 'tracking');
    await commonChecks(page, 'S03');
    await shot(page, 'S03-light');
  });

  test('opened directly without a record: no proceed, still readable', async ({ page, ext }) => {
    const w = watch(page);
    await page.goto(`${ext.origin}/pages/blocked.html?list=urlhaus`);
    await page.waitForFunction(() => document.body.dataset.state === 'ready');
    await expect(page.locator('#bl-proceed')).toBeHidden();
    await expect(page.locator('#bl-host')).toBeHidden();
    await expect(page.locator('#bl-text')).toHaveText(/Filterliste/);
    await commonChecks(page, 'no record');
    expect.soft(w.failed).toEqual([]);
  });
});

test.describe('bounce page (S08–S10)', () => {
  test.beforeEach(async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { ui: { language: 'de' } } }, 3000);
  });

  test('S08: skipped, names the destination and links to it', async ({ page, server, ext }) => {
    const w = watch(page);
    await page.setViewportSize({ width: 768, height: 460 });
    const dest = `www.${HOSTS.B}`;
    const target = server.url(dest, '/hang/product?id=1');
    // The destination answers 204 No Content, so the browser stays on the bounce page.
    server.route(dest, /^\/hang\//, (_req, res) => {
      res.writeHead(204);
      res.end();
    });
    void page.goto(`${ext.origin}/pages/bounce.html#${encodeURIComponent(target)}`, { waitUntil: 'commit' }).catch(() => {});
    await page.waitForFunction(() => document.body?.dataset.state === 'ok');
    // Locators would wait for the held navigation; read the DOM directly.
    await page.waitForFunction(() => !document.body.dataset.lang && document.getElementById('bn-ok-title')?.textContent === 'Tracker-Umweg übersprungen');
    const s08 = await page.evaluate(() => {
      const link = document.getElementById('bn-link') as HTMLAnchorElement;
      return {
        text: (document.querySelector('.bn-ok .bn-text') as HTMLElement).innerText,
        href: link.href,
        translate: link.getAttribute('translate'),
        tile: document.querySelector('.bn-ok .tile')?.getAttribute('aria-hidden'),
      };
    });
    expect(s08.text).toBe(`Weiter zu ${dest}`);
    expect(s08.href, 'the host links to the destination').toBe(target);
    expect(s08.translate).toBe('no');
    expect(s08.tile).toBe('true');
    await commonChecks(page, 'S08');
    for (const scheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
      await shot(page, `S08-${scheme}`);
    }
    expect.soft(w.failed).toEqual([]);
  });

  test('S09: same-site redirect offers «Ziel öffnen» and «Zurück»', async ({ page, server, ext }) => {
    const w = watch(page);
    const target = server.setPage(HOSTS.A, '/e2e/same-site-target.html', '<!doctype html><meta charset="utf-8"><title>target</title><p>target');
    const start = server.setPage(HOSTS.B, '/e2e/same-site-start.html', '<!doctype html><meta charset="utf-8"><title>start</title><p>start');
    const bounce = `${ext.origin}/pages/bounce.html?from=${encodeURIComponent('click.' + HOSTS.A)}#${encodeURIComponent(target)}`;
    await page.goto(start);
    await page.goto(bounce);
    await page.waitForFunction(() => document.body.dataset.state === 'samesite');
    await expect(page.locator('#bn-same-title')).toHaveText('Normale Weiterleitung');
    await expect(page.locator('.bn-same .bn-text')).toHaveText(`Kein Tracking. Ziel: ${HOSTS.A}`);
    await expect(page.locator('#bn-same-host')).toHaveAttribute('translate', 'no');
    await expect(page.locator('#bn-same-link')).toHaveText('Ziel öffnen');
    await commonChecks(page, 'S09');
    for (const scheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
      await shot(page, `S09-${scheme}`);
    }
    // «Zurück» returns to the previous page.
    await page.locator('#bn-same-back').click();
    await page.waitForURL(start, { timeout: 5000 });
    // «Ziel öffnen» opens the destination.
    await page.goto(bounce);
    await page.waitForFunction(() => document.body.dataset.state === 'samesite');
    await page.locator('#bn-same-link').focus();
    await page.keyboard.press('Enter');
    await page.waitForURL(target, { timeout: 5000 });
    expect(page.url()).toBe(target);
    expect.soft(w.failed).toEqual([]);
  });

  test('S10: invalid destination; «Zurück» works without history', async ({ ext }) => {
    const p = await ext.context.newPage();
    const w = watch(p);
    await p.goto(`${ext.origin}/pages/bounce.html#${encodeURIComponent('javascript:alert(1)')}`);
    await p.waitForFunction(() => document.body.dataset.state === 'invalid');
    await expect(p.locator('#bn-invalid-title')).toHaveText('Ungültiges Ziel');
    await expect(p.locator('#bn-invalid-text')).toHaveText('Bastion Shield öffnet diese Adresse nicht.');
    await expect(p.locator('#bn-invalid-text span[translate="no"]')).toHaveText('Bastion Shield');
    await commonChecks(p, 'S10');
    for (const scheme of ['light', 'dark'] as const) {
      await p.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
      await shot(p, `S10-${scheme}`);
    }
    const len = await p.evaluate(() => history.length);
    await p.locator('#bn-back').click();
    await p.waitForURL((u) => !u.href.includes('/pages/bounce.html'), { timeout: 5000 });
    console.log(`[bounce] «Zurück» with history.length=${len} -> ${p.url()}`);
    expect(p.url()).not.toContain('/pages/bounce.html');
    expect.soft(w.failed).toEqual([]);
    await p.close();
  });

  test('S08 with a very long destination host at 390px', async ({ page, server, ext }) => {
    await page.setViewportSize({ width: 390, height: 700 });
    const host = `very-long-subdomain-name-for-a-shop-campaign-landing-2026.deals.${HOSTS.A}`;
    server.route(host, /^\/hang\//, (_req, res) => {
      res.writeHead(204);
      res.end();
    });
    void page.goto(`${ext.origin}/pages/bounce.html#${encodeURIComponent(server.url(host, '/hang/x'))}`, { waitUntil: 'commit' }).catch(() => {});
    await page.waitForFunction(() => document.body?.dataset.state === 'ok');
    const link = await page.evaluate(() => {
      const el = document.getElementById('bn-link')!;
      return { title: el.title, text: el.textContent ?? '' };
    });
    expect(link.title, 'full host in title').toBe(host);
    expect(link.text, 'long host cut in the middle').toContain('…');
    await commonChecks(page, 'S08 long');
  });
});
