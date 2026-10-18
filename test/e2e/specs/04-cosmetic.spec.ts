// Bastion Shield e2e — (g) cosmetic filtering: lowly generic selectors (token
// surveyor, incl. nodes added later), highly generic CSS, hostname-specific
// selectors from the shards, and $generichide exceptions.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { Page } from '@playwright/test';
import { expect, test } from '../support/fixtures.ts';
import { HOSTS } from '../support/hosts.ts';
import { poll } from '../support/pages.ts';
import { elementHtml, pickGenerichideHost, pickGenericSelectors, pickHighGenericSelector, pickSpecificSelectors } from '../support/pickers.ts';

async function displayOf(page: Page, probe: string): Promise<string> {
  return page
    .locator(`[data-bx-probe="${probe}"]`)
    .evaluate((e) => getComputedStyle(e).display)
    .catch((e) => 'error: ' + String(e));
}

async function matches(page: Page, probe: string, selector: string): Promise<boolean> {
  return page.locator(`[data-bx-probe="${probe}"]`).evaluate((e, s) => e.matches(s), selector).catch(() => false);
}

function cosmeticPage(title: string, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body>
<p data-bx-probe="control" class="article-body">Regular content must stay visible.</p>
${body}
</body></html>`;
}

test.describe('cosmetic filtering', () => {
  test('(g) generic selectors hide matching elements, including ones added after load', async ({ page, server, dist }) => {
    const picks = pickGenericSelectors(dist, 3);
    expect(picks.length, 'lowly generic selectors in dist/cosmetic/generic.json').toBeGreaterThan(0);
    const high = pickHighGenericSelector(dist);
    const body = picks.map((p, i) => elementHtml(p.element, `g${i}`)).join('\n') + (high ? '\n' + elementHtml(high.element, 'high') : '');
    // A late element, inserted after DOMContentLoaded, exercises the MutationObserver path.
    const late = picks[0];
    const lateHtml = elementHtml(late.element, 'late');
    const script = `<script>setTimeout(function(){document.body.insertAdjacentHTML('beforeend', ${JSON.stringify(lateHtml)});}, 600);</script>`;
    const url = server.setPage(HOSTS.A, '/e2e/cosmetic-generic.html', cosmeticPage('generic', body + script));
    await page.goto(url);
    for (let i = 0; i < picks.length; i++) {
      expect(await matches(page, `g${i}`, picks[i].selector), `fixture element matches ${picks[i].selector}`).toBe(true);
      const d = await poll(() => displayOf(page, `g${i}`), (v) => v === 'none', 5000);
      expect.soft(d, `generic ${picks[i].selector} (token ${picks[i].token}, lists ${picks[i].lists.join(',')}) is hidden`).toBe('none');
    }
    if (high) {
      expect(await matches(page, 'high', high.selector), `fixture element matches ${high.selector}`).toBe(true);
      const d = await poll(() => displayOf(page, 'high'), (v) => v === 'none', 5000);
      expect.soft(d, `highly generic ${high.selector} (${high.listId}) is hidden`).toBe('none');
    }
    await page.locator('[data-bx-probe="late"]').waitFor({ state: 'attached', timeout: 5000 });
    const dl = await poll(() => displayOf(page, 'late'), (v) => v === 'none', 5000);
    expect.soft(dl, `late-inserted ${late.selector} is hidden by the surveyor`).toBe('none');
    expect(await displayOf(page, 'control'), 'regular content stays visible').not.toBe('none');
  });

  test('(g) hostname-specific selectors hide elements on their site only', async ({ page, server, dist }) => {
    const picks = pickSpecificSelectors(dist, 2);
    expect(picks.length, 'hostname-specific hide filters in dist/cosmetic/specific').toBeGreaterThan(0);
    for (const [i, p] of picks.entries()) {
      const html = cosmeticPage('specific', elementHtml(p.element, `s${i}`));
      const url = server.setPage(p.host, `/e2e/cosmetic-specific-${i}.html`, html);
      await page.goto(url);
      expect(new URL(page.url()).hostname, `page loaded on ${p.host}`).toBe(p.host);
      expect(await matches(page, `s${i}`, p.selector), `fixture element matches ${p.selector}`).toBe(true);
      const d = await poll(() => displayOf(page, `s${i}`), (v) => v === 'none', 5000);
      expect.soft(d, `${p.host}##${p.selector} (${p.lists.join(',')}) is hidden`).toBe('none');
      // Same markup on an unrelated site: a specific filter must not leak.
      const other = server.setPage(HOSTS.C, `/e2e/cosmetic-specific-other-${i}.html`, html);
      await page.goto(other);
      await page.waitForTimeout(500);
      const generic = await displayOf(page, `s${i}`);
      // Some specific selectors are also generic ones; only assert when the selector is not in generic data.
      const tokens = dist.genericIndex().tokens ?? {};
      const alsoGeneric = Object.values(tokens).some((arr) => arr.some(([s]) => s === p.selector)) || Object.values(dist.genericHigh()).some((arr) => arr.includes(p.selector));
      if (!alsoGeneric) expect.soft(generic, `${p.selector} not applied on ${HOSTS.C}`).not.toBe('none');
    }
  });

  test('(g) $generichide exception disables generic hiding on that host', async ({ page, server, dist }) => {
    const gh = pickGenerichideHost(dist);
    test.skip(!gh, 'no host with a generichide flag in the enabled lists');
    const picks = pickGenericSelectors(dist, 1);
    expect(picks.length).toBeGreaterThan(0);
    const p = picks[0];
    const html = cosmeticPage('generichide', elementHtml(p.element, 'gh'));
    const url = server.setPage(gh!.host, '/e2e/generichide.html', html);
    await page.goto(url);
    expect(new URL(page.url()).hostname).toBe(gh!.host);
    await page.waitForTimeout(1500); // longer than a surveyor flush + SW round trip
    const d = await displayOf(page, 'gh');
    expect(d, `generic ${p.selector} stays visible on ${gh!.host} (generichide from ${gh!.lists.join(',')})`).not.toBe('none');
    // Control: the same element is hidden on a normal site.
    const ctl = server.setPage(HOSTS.A, '/e2e/generichide-control.html', html);
    await page.goto(ctl);
    const dc = await poll(() => displayOf(page, 'gh'), (v) => v === 'none', 5000);
    expect(dc, `control: ${p.selector} hidden on ${HOSTS.A}`).toBe('none');
  });
});
