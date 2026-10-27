// Bastion Shield e2e — Standard-mode first-party un-hiding (Brave parity,
// ARCHITECTURE §5.2.8): a first-party ad container hidden by a selector that
// only first-party-protected lists have stays visible in Standard mode and
// is hidden in Aggressive mode; a third-party ad container stays hidden in
// both.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { Page } from '@playwright/test';
import { expect, test } from '../support/fixtures.ts';
import { HOSTS } from '../support/hosts.ts';
import { poll } from '../support/pages.ts';
import { elementForSelector, pickHighGenericSelector, pickSoftGenericSelectors } from '../support/pickers.ts';
import type { ElementSpec } from '../support/pickers.ts';

/** The un-hiding starts on idle within 2.5 s and works through every soft selector three times. */
const SETTLE_MS = 12_000;

async function displayOf(page: Page, probe: string): Promise<string> {
  return page
    .locator(`[data-bx-probe="${probe}"]`)
    .evaluate((e) => getComputedStyle(e).display)
    .catch((e) => 'error: ' + String(e));
}

function open(el: ElementSpec, probe: string): string {
  const a = Object.entries(el.attrs)
    .map(([k, v]) => ` ${k}="${v.replace(/&/g, '&amp;').replace(/"/g, '&quot;')}"`)
    .join('');
  return `<${el.tag}${a} data-bx-probe="${probe}" style="min-height:10px">`;
}

/** A first-party ad slot, as on 20min.ch: a first-party image and a teaser line. */
function firstParty(el: ElementSpec, probe: string): string {
  return `${open(el, probe)}<a href="/promo"><img src="/img/teaser.jpg" alt="" width="10" height="10"> Promotion</a></${el.tag}>`;
}

/** A classic third-party ad slot: the creative comes from another site. */
function thirdParty(el: ElementSpec, probe: string): string {
  return `${open(el, probe)}<img src="https://${HOSTS.CDN}/creative/banner.gif" alt="" width="10" height="10"></${el.tag}>`;
}

function page(body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>unhide</title></head><body>
<p data-bx-probe="control">Regular content must stay visible.</p>
${body}
</body></html>`;
}

test.describe('Standard-mode un-hiding (Brave parity)', () => {
  test.afterEach(async ({ ext }) => {
    await ext.sendAndApply({ type: 'sites:set', sites: {} }, 3000);
    await ext.sendAndApply({ type: 'settings:set', patch: { defaultMode: 'standard' } }, 3000);
  });

  test('first-party ad container: visible in Standard, hidden in Aggressive; third-party one hidden in both', async ({ page: tab, server, dist, ext }) => {
    const picks = pickSoftGenericSelectors(dist, 2);
    expect(picks.length, 'two generic selectors that only first-party-protected lists have').toBe(2);
    const [fp, tp] = picks;
    const high = pickHighGenericSelector(dist);
    const highEl = high ? elementForSelector(high.selector) : null;
    const body = [firstParty(fp.element, 'fp'), thirdParty(tp.element, 'tp'), high && highEl ? firstParty(highEl, 'fp-high') : ''].join('\n');
    const url = server.setPage(HOSTS.A, '/e2e/unhide.html', page(body));
    const info = `${fp.selector} (${fp.lists.join(',')}), ${tp.selector} (${tp.lists.join(',')})${high ? `, ${high.selector} (${high.listId})` : ''}`;

    // Standard (the default).
    await tab.goto(url);
    // The soft selectors are hidden first (the third-party box shows they arrived) ...
    const tpStd = await poll(() => displayOf(tab, 'tp'), (v) => v === 'none', 5000);
    expect(tpStd, `Standard: third-party container ${tp.selector} is hidden [${info}]`).toBe('none');
    // ... then the first-party ones are un-hidden.
    const fpStd = await poll(() => displayOf(tab, 'fp'), (v) => v !== 'none', SETTLE_MS, 250);
    expect(fpStd, `Standard: first-party container ${fp.selector} is un-hidden [${info}]`).not.toBe('none');
    if (high && highEl) {
      const d = await poll(() => displayOf(tab, 'fp-high'), (v) => v !== 'none', SETTLE_MS, 250);
      expect.soft(d, `Standard: first-party container of highly generic ${high.selector} is un-hidden`).not.toBe('none');
    }
    await tab.waitForTimeout(1000);
    expect(await displayOf(tab, 'tp'), `Standard: third-party container ${tp.selector} stays hidden`).toBe('none');
    expect(await displayOf(tab, 'fp'), 'Standard: the first-party container stays visible').not.toBe('none');
    expect(await displayOf(tab, 'control')).not.toBe('none');

    // Aggressive for the site: uBO-style hiding, nothing is un-hidden.
    const r = await ext.sendAndApply<{ error?: string }>({ type: 'site:set', site: HOSTS.A, patch: { mode: 'aggressive' } });
    expect(r.response?.error, 'site:set mode=aggressive').toBeUndefined();
    await tab.goto(url);
    const fpAgg = await poll(() => displayOf(tab, 'fp'), (v) => v === 'none', 5000);
    expect(fpAgg, `Aggressive: first-party container ${fp.selector} is hidden`).toBe('none');
    // Longer than the Standard-mode check needs: it must stay hidden.
    await tab.waitForTimeout(4000);
    expect(await displayOf(tab, 'fp'), 'Aggressive: still hidden after the un-hide window').toBe('none');
    if (high && highEl) expect.soft(await displayOf(tab, 'fp-high'), `Aggressive: highly generic ${high.selector} hides`).toBe('none');
    expect(await displayOf(tab, 'tp')).toBe('none');
    expect(await displayOf(tab, 'control')).not.toBe('none');
  });
});
