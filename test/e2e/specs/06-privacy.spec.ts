// Bastion Shield e2e — privacy features: (i) tracking-parameter stripping on
// cross-site navigations, (j) Global Privacy Control, (k) fingerprinting
// protection (canvas farbling per site and per session).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { Page } from '@playwright/test';
import { RULESET_PARAMS } from '../../../src/shared/constants.ts';
import type { Dist } from '../support/dist.ts';
import { expect, test } from '../support/fixtures.ts';
import { HOSTS } from '../support/hosts.ts';
import { poll } from '../support/pages.ts';
import { FIXTURES_DIR } from '../support/paths.ts';
import type { FixtureServer } from '../support/server.ts';

/**
 * A parameter that only Brave's query filter (bastion-params) removes, so its
 * fate shows the cross-site-only semantics. fbclid itself is also removed on
 * every navigation by uBO Privacy's generic `$removeparam=fbclid` (on by
 * default, as in Brave), so it cannot show that.
 */
function braveOnlyParam(dist: Dist): string | null {
  const others = new Set<string>();
  const enabled = new Set(dist.expectedDefaultRulesets() ?? dist.manifestEnabledRulesets());
  for (const id of enabled) {
    if (id === RULESET_PARAMS) continue;
    for (const r of dist.rules(id)) for (const p of r.action.redirect?.transform?.queryTransform?.removeParams ?? []) others.add(p);
    // Also skip anything a generic urlFilter mentions (e.g. "^mc_eid=").
    for (const r of dist.rules(id)) {
      const m = /\^([A-Za-z0-9_]+)=/.exec(r.condition.urlFilter ?? '');
      if (m && r.action.type === 'redirect') others.add(m[1]);
    }
  }
  const candidates: string[] = [];
  for (const r of dist.rules(RULESET_PARAMS)) {
    if (r.condition.requestDomains || r.condition.initiatorDomains) continue;
    for (const p of r.action.redirect?.transform?.queryTransform?.removeParams ?? []) if (!others.has(p) && /^[A-Za-z0-9_]+$/.test(p)) candidates.push(p);
  }
  const prefer = ['mc_eid', '__hsfp', 'oly_anon_id', 'ml_subscriber', 'bsft_uid'];
  return prefer.find((p) => candidates.includes(p)) ?? candidates.sort()[0] ?? null;
}

async function navigateViaLink(page: Page, server: FixtureServer, fromHost: string, target: string): Promise<{ query: URLSearchParams; finalUrl: string }> {
  const src = server.setPage(fromHost, '/e2e/link.html', `<!doctype html><meta charset="utf-8"><title>link</title><a id="go" href="${target.replace(/&/g, '&amp;')}">go</a>`);
  await page.goto(src);
  const t0 = Date.now();
  const u = new URL(target);
  await Promise.all([page.waitForURL((x) => x.hostname === u.hostname, { timeout: 10_000 }).catch(() => {}), page.click('#go')]);
  const hit = await server.waitForHit((h) => h.t >= t0 && h.host === u.hostname && h.pathname === u.pathname, 5000);
  return { query: new URLSearchParams(hit?.query ?? 'missing=1'), finalUrl: page.url() };
}

test.describe('tracking parameters', () => {
  test.afterEach(async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { privacy: { stripParams: true } } }, 3000);
    await ext.sendAndApply({ type: 'lists:set', listId: 'url-tracking', enabled: false }, 3000);
  });

  test('(i) fbclid is stripped on cross-site navigation, utm_source kept unless url-tracking is on', async ({ page, server, ext, dist }) => {
    const enabled = await ext.api(() => chrome.declarativeNetRequest.getEnabledRulesets());
    expect(enabled, `${RULESET_PARAMS} enabled by default`).toContain(RULESET_PARAMS);
    const target = server.url(HOSTS.B, '/landing.html') + '?fbclid=x&utm_source=y&keep=1';

    const cross = await navigateViaLink(page, server, HOSTS.A, target);
    expect(cross.query.get('missing'), 'site-b received the navigation').toBeNull();
    expect.soft(cross.query.has('fbclid'), `fbclid stripped (cross-site), final URL ${cross.finalUrl}`).toBe(false);
    expect.soft(cross.query.get('utm_source'), 'utm_source kept (url-tracking list off by default)').toBe('y');
    expect.soft(cross.query.get('keep'), 'unrelated parameter kept').toBe('1');

    // Brave's query filter applies to cross-site navigations only.
    const bp = braveOnlyParam(dist);
    expect(bp, 'a parameter that only bastion-params strips').toBeTruthy();
    const crossBp = await navigateViaLink(page, server, HOSTS.A, server.url(HOSTS.B, '/landing-bp.html') + `?${bp}=x&keep=1`);
    expect.soft(crossBp.query.has(bp!), `${bp} stripped on cross-site navigation`).toBe(false);
    const sameSite = await navigateViaLink(page, server, HOSTS.A, server.url(HOSTS.A_SUB, '/landing.html') + `?${bp}=x&keep=1`);
    expect.soft(sameSite.query.get(bp!), `${bp} kept on same-site navigation`).toBe('x');

    // url-tracking list on -> utm_source is removed as well (uBO $removeparam).
    if (dist.list('url-tracking')) {
      const r = await ext.sendAndApply<{ error?: string }>({ type: 'lists:set', listId: 'url-tracking', enabled: true });
      expect(r.response?.error, 'lists:set url-tracking').toBeUndefined();
      const withList = await navigateViaLink(page, server, HOSTS.A, target);
      expect.soft(withList.query.has('utm_source'), 'utm_source stripped with url-tracking list on').toBe(false);
      expect.soft(withList.query.has('fbclid'), 'fbclid still stripped').toBe(false);
    }

    // stripParams off -> parameters survive.
    await ext.sendAndApply({ type: 'lists:set', listId: 'url-tracking', enabled: false }, 3000);
    const off = await ext.sendAndApply<{ error?: string }>({ type: 'settings:set', patch: { privacy: { stripParams: false } } });
    expect(off.response?.error).toBeUndefined();
    const offEnabled = await ext.api(() => chrome.declarativeNetRequest.getEnabledRulesets());
    expect.soft(offEnabled, `${RULESET_PARAMS} disabled with stripParams off`).not.toContain(RULESET_PARAMS);
    const offNav = await navigateViaLink(page, server, HOSTS.A, server.url(HOSTS.B, '/landing-bp.html') + `?${bp}=x&keep=1`);
    expect.soft(offNav.query.get(bp!), `${bp} kept with stripParams off`).toBe('x');
  });
});

test.describe('Global Privacy Control', () => {
  test.afterEach(async ({ ext }) => {
    await ext.sendAndApply({ type: 'settings:set', patch: { privacy: { gpc: true } } }, 3000);
  });

  test('(j) Sec-GPC: 1 reaches the server and navigator.globalPrivacyControl is true', async ({ page, server, ext }) => {
    const t0 = Date.now();
    const url = server.setPage(HOSTS.A, '/e2e/gpc.html', `<!doctype html><meta charset="utf-8"><title>gpc</title><img src="${server.url(HOSTS.CDN, '/gpc-pixel.gif')}">`);
    await page.goto(url, { waitUntil: 'load' });
    const doc = server.hits.find((h) => h.t >= t0 && h.host === HOSTS.A && h.pathname === '/e2e/gpc.html');
    const sub = await server.waitForHit((h) => h.t >= t0 && h.host === HOSTS.CDN && h.pathname === '/gpc-pixel.gif', 3000);
    expect(doc?.headers['sec-gpc'], 'Sec-GPC on the document request').toBe('1');
    expect.soft(sub?.headers['sec-gpc'], 'Sec-GPC on a third-party subresource').toBe('1');
    const gpc = await page.evaluate(() => (navigator as unknown as { globalPrivacyControl?: boolean }).globalPrivacyControl);
    expect(gpc, 'navigator.globalPrivacyControl').toBe(true);

    const off = await ext.sendAndApply({ type: 'settings:set', patch: { privacy: { gpc: false } } });
    expect(off.applied, 'gpc=false applied').toBe(true);
    const t1 = Date.now();
    await page.goto(url, { waitUntil: 'load' });
    const doc2 = server.hits.find((h) => h.t >= t1 && h.host === HOSTS.A && h.pathname === '/e2e/gpc.html');
    // Chromium itself never sends Sec-GPC, so the header disappears entirely.
    expect.soft(doc2?.headers['sec-gpc'], 'no Sec-GPC with gpc off').toBeUndefined();
  });
});

interface CanvasProbe {
  urlHash: string;
  dataHash: string;
  blankUrlHash: string;
  blankNonZero: boolean;
  toDataURLNative: boolean;
  hardwareConcurrency: number;
}

async function canvasProbe(page: Page): Promise<CanvasProbe> {
  return page.evaluate(() => {
    const fnv = (s: string | Uint8ClampedArray): string => {
      let h = 0x811c9dc5;
      if (typeof s === 'string') for (let i = 0; i < s.length; i++) (h ^= s.charCodeAt(i)), (h = Math.imul(h, 0x01000193));
      else for (let i = 0; i < s.length; i++) (h ^= s[i]), (h = Math.imul(h, 0x01000193));
      return (h >>> 0).toString(16);
    };
    const c = document.createElement('canvas');
    c.width = 240;
    c.height = 60;
    const g = c.getContext('2d')!;
    g.textBaseline = 'top';
    g.font = '16px Arial';
    g.fillStyle = '#f60';
    g.fillRect(100, 1, 62, 20);
    g.fillStyle = '#069';
    g.fillText('Bastion Shield fp test ✓', 2, 15);
    g.fillStyle = 'rgba(102, 204, 0, 0.7)';
    g.fillText('Bastion Shield fp test ✓', 4, 17);
    const grad = g.createLinearGradient(0, 0, 240, 0);
    grad.addColorStop(0, '#2A3134');
    grad.addColorStop(1, '#C8102E');
    g.fillStyle = grad;
    g.fillRect(0, 40, 240, 20);
    const url = c.toDataURL();
    const data = g.getImageData(0, 0, c.width, c.height).data;
    const b = document.createElement('canvas');
    b.width = 64;
    b.height = 64;
    const bg = b.getContext('2d')!;
    const blank = bg.getImageData(0, 0, 64, 64).data;
    return {
      urlHash: fnv(url),
      dataHash: fnv(data),
      blankUrlHash: fnv(b.toDataURL()),
      blankNonZero: blank.some((v) => v !== 0),
      toDataURLNative: /\[native code\]/.test(Function.prototype.toString.call(HTMLCanvasElement.prototype.toDataURL)),
      hardwareConcurrency: navigator.hardwareConcurrency,
    };
  });
}

test.describe('fingerprinting protection', () => {
  test.afterEach(async ({ ext }) => {
    await ext.sendAndApply({ type: 'sites:set', sites: {} }, 3000);
  });

  test('(k) canvas readouts are stable per site, differ across sites, and are real with protection off', async ({ page, server, ext }, testInfo) => {
    // Use the content agent's fixture page when present (it may print its own
    // readouts); the measurement itself is ours so it does not depend on it.
    const fpPath = existsSync(path.join(FIXTURES_DIR, 'fingerprint.html')) ? '/fingerprint.html' : '/e2e/fp.html';
    if (fpPath !== '/fingerprint.html') server.setPage('*', fpPath, '<!doctype html><meta charset="utf-8"><title>fp</title><p>fp</p>');
    const load = async (host: string) => {
      await page.goto(server.url(host, fpPath), { waitUntil: 'load' });
      return canvasProbe(page);
    };
    const a1 = await load(HOSTS.A);
    const a2 = await load(HOSTS.A);
    const b1 = await load(HOSTS.B);
    const c1 = await load(HOSTS.C);

    for (const h of [HOSTS.A, HOSTS.C]) {
      const r = await ext.sendAndApply<{ error?: string }>({ type: 'site:set', site: h, patch: { fingerprinting: 'off' } });
      expect(r.response?.error, `site:set fingerprinting=off for ${h}`).toBeUndefined();
    }
    const aOff = await load(HOSTS.A);
    const cOff = await load(HOSTS.C);
    const report = { a1, a2, b1, c1, aOff, cOff };
    await testInfo.attach('canvas', { body: JSON.stringify(report, null, 2), contentType: 'application/json' });
    console.log('[fingerprint] ' + JSON.stringify({ a: a1.urlHash, a2: a2.urlHash, b: b1.urlHash, c: c1.urlHash, aOff: aOff.urlHash, cOff: cOff.urlHash }));

    expect.soft(a2.urlHash, 'toDataURL stable within a site and session').toBe(a1.urlHash);
    expect.soft(a2.dataHash, 'getImageData stable within a site and session').toBe(a1.dataHash);
    expect.soft(b1.urlHash, 'toDataURL differs across sites').not.toBe(a1.urlHash);
    expect.soft(c1.urlHash, 'toDataURL differs across sites (2)').not.toBe(a1.urlHash);
    expect.soft(aOff.urlHash, 'protection off: real readout is the same on every site').toBe(cOff.urlHash);
    expect.soft(aOff.urlHash, 'farbled readout differs from the real one').not.toBe(a1.urlHash);
    expect.soft(aOff.dataHash, 'farbled getImageData differs from the real one').not.toBe(a1.dataHash);
    expect.soft(a1.blankNonZero, 'blank canvas stays all-zero').toBe(false);
    expect.soft(a1.blankUrlHash, 'blank canvas toDataURL unchanged by farbling').toBe(aOff.blankUrlHash);
    expect.soft(a1.toDataURLNative, 'patched toDataURL still stringifies as native code').toBe(true);
    const cpus = os.cpus().length;
    expect.soft(a1.hardwareConcurrency, 'hardwareConcurrency <= real').toBeLessThanOrEqual(Math.max(aOff.hardwareConcurrency, cpus));
    if (aOff.hardwareConcurrency >= 2) expect.soft(a1.hardwareConcurrency, 'hardwareConcurrency >= 2').toBeGreaterThanOrEqual(2);

    // Settled state check: once re-enabled, the farbled value comes back (same session seed).
    await ext.sendAndApply({ type: 'site:set', site: HOSTS.A, patch: { fingerprinting: 'standard' } });
    const aBack = await poll(() => load(HOSTS.A), (v) => v.urlHash === a1.urlHash, 3000, 300);
    expect.soft(aBack.urlHash, 'same farbled readout after re-enabling (session seed unchanged)').toBe(a1.urlHash);
  });
});
