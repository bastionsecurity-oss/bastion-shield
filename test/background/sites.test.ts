// Tests for site keys, per-site resolution and the include/exclude layering
// used by DNR rules and content-script match patterns (src/background/sites.ts).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  coveredBy,
  effectiveSites,
  isFilterableUrl,
  keepPolicyOwnedFields,
  isSameOrSubdomain,
  layerScopes,
  normalizeSiteKey,
  patchSite,
  resolveSite,
  sanitizeSites,
  siteKeyFromUrl,
} from '../../src/background/sites.ts';
import type { ScopeGroup } from '../../src/background/sites.ts';
import { defaultSettings } from '../../src/background/settings.ts';
import { hostnameCandidates } from '../../src/shared/hash.ts';

test('normalizeSiteKey handles URLs, wildcards, ports, IDN and garbage', () => {
  assert.equal(normalizeSiteKey('https://www.Example.com/path?q=1'), 'example.com');
  assert.equal(normalizeSiteKey('*.example.com'), 'example.com');
  assert.equal(normalizeSiteKey('||ads.example.com^'), 'ads.example.com');
  assert.equal(normalizeSiteKey('example.com:8080'), 'example.com');
  assert.equal(normalizeSiteKey('bücher.ch'), 'xn--bcher-kva.ch');
  assert.equal(normalizeSiteKey('example.com.'), 'example.com');
  assert.equal(normalizeSiteKey('192.168.1.10'), '192.168.1.10');
  assert.equal(normalizeSiteKey('[::1]'), '[::1]');
  assert.equal(normalizeSiteKey('localhost'), 'localhost');
  assert.equal(normalizeSiteKey('www.ch'), 'www.ch');
  assert.equal(normalizeSiteKey(''), null);
  assert.equal(normalizeSiteKey('exa mple.com'), null);
  assert.equal(normalizeSiteKey('a.*.com'), null);
  assert.equal(normalizeSiteKey(42), null);
});

test('siteKeyFromUrl and isFilterableUrl', () => {
  assert.equal(siteKeyFromUrl('https://www.nzz.ch/'), 'nzz.ch');
  assert.equal(siteKeyFromUrl('chrome://settings'), null);
  assert.equal(siteKeyFromUrl('not a url'), null);
  assert.equal(isFilterableUrl('https://www.nzz.ch/'), true);
  assert.equal(isFilterableUrl('http://intranet/'), true);
  assert.equal(isFilterableUrl('chrome-extension://abc/ui/popup.html'), false);
  assert.equal(isFilterableUrl('https://chromewebstore.google.com/detail/x'), false);
  assert.equal(isFilterableUrl('https://chrome.google.com/webstore/detail/x'), false);
  assert.equal(isFilterableUrl('https://microsoftedge.microsoft.com/addons/detail/x'), false);
  assert.equal(isFilterableUrl('edge://settings'), false);
});

test('isSameOrSubdomain', () => {
  assert.equal(isSameOrSubdomain('a.example.com', 'example.com'), true);
  assert.equal(isSameOrSubdomain('example.com', 'example.com'), true);
  assert.equal(isSameOrSubdomain('badexample.com', 'example.com'), false);
});

test('sanitizeSites and patchSite', () => {
  const s = sanitizeSites({ 'WWW.Example.com': { enabled: false, mode: 'weird' }, '': { enabled: false }, 'x.ch': { foo: 1 } });
  assert.deepEqual(s, { 'example.com': { enabled: false } });
  const p = patchSite(s, 'example.com', { enabled: null, mode: 'aggressive' });
  assert.deepEqual(p, { 'example.com': { mode: 'aggressive' } });
  const q = patchSite(p, 'example.com', { mode: null });
  assert.deepEqual(q, {});
  assert.deepEqual(s, { 'example.com': { enabled: false } }, 'input not mutated');
});

test('effectiveSites overlays the policy', () => {
  const user = { 'a.ch': { enabled: false }, 'b.ch': { mode: 'standard' as const } };
  const eff = effectiveSites(user, { disabledSites: ['https://intranet.muster.ch/'], aggressiveSites: ['b.ch'] });
  assert.deepEqual(eff['intranet.muster.ch'], { enabled: false });
  assert.deepEqual(eff['b.ch'], { mode: 'aggressive' });
  assert.deepEqual(eff['a.ch'], { enabled: false });
  // allowUserSiteToggle:false drops the user's own "off" switches.
  const locked = effectiveSites(user, { allowUserSiteToggle: false });
  assert.equal(locked['a.ch'], undefined);
});

test('resolveSite walks parents per field', () => {
  const settings = defaultSettings();
  const sites = { 'example.com': { enabled: false, fingerprinting: 'strict' as const }, 'shop.example.com': { enabled: true } };
  assert.deepEqual(resolveSite('www.shop.example.com', sites, settings), { enabled: true, mode: 'standard', blockScripts: false, fingerprinting: 'strict' });
  assert.equal(resolveSite('news.example.com', sites, settings).enabled, false);
  assert.equal(resolveSite('other.ch', sites, settings).enabled, true);
});

/** Effective value of a host according to the groups (reference semantics). */
function valueFromGroups<V>(groups: ScopeGroup<V>[], host: string): V[] {
  const cands = hostnameCandidates(host);
  const under = (list: string[]) => list.some((s) => cands.includes(s));
  return groups.filter((g) => (g.include === null || under(g.include)) && !under(g.exclude)).map((g) => g.value);
}

test('layerScopes partitions hosts exactly, for nested overrides', () => {
  const explicit = new Map<string, boolean>([
    ['example.com', false],
    ['shop.example.com', true],
    ['cart.shop.example.com', false],
    ['x.cart.shop.example.com', true],
    ['news.example.com', false], // same as inherited: not a boundary
    ['other.ch', true], // same as root
  ]);
  const groups = layerScopes(explicit, true);
  const expect: [string, boolean][] = [
    ['example.com', false],
    ['www.example.com', false],
    ['shop.example.com', true],
    ['a.shop.example.com', true],
    ['cart.shop.example.com', false],
    ['y.cart.shop.example.com', false],
    ['x.cart.shop.example.com', true],
    ['news.example.com', false],
    ['other.ch', true],
    ['unrelated.org', true],
  ];
  for (const [host, value] of expect) {
    const vals = valueFromGroups(groups, host);
    assert.deepEqual(vals, [value], `${host} -> ${JSON.stringify(vals)}`);
  }
  // Root group excludes only top-level boundaries.
  const root = groups.find((g) => g.include === null)!;
  assert.deepEqual(root.exclude, ['example.com']);
});

test('layerScopes with no overrides is just the root', () => {
  const groups = layerScopes(new Map<string, string>(), 'standard');
  assert.equal(groups.length, 1);
  assert.equal(groups[0].include, null);
  assert.deepEqual(groups[0].exclude, []);
});

test('layerScopes groups same-value siblings', () => {
  const groups = layerScopes(
    new Map<string, string>([
      ['a.ch', 'strict'],
      ['b.ch', 'strict'],
      ['c.ch', 'off'],
    ]),
    'standard',
  );
  const strict = groups.find((g) => g.value === 'strict')!;
  assert.deepEqual(strict.include, ['a.ch', 'b.ch']);
  assert.deepEqual(groups.find((g) => g.include === null)!.exclude, ['a.ch', 'b.ch', 'c.ch']);
});

test('effectiveSites: aggressiveSites wins on subdomains too (ENT-4)', () => {
  const user = { 'shop.example.com': { mode: 'standard' as const, blockScripts: true }, 'other.ch': { mode: 'standard' as const } };
  const eff = effectiveSites(user, { aggressiveSites: ['example.com'] });
  assert.deepEqual(eff['shop.example.com'], { mode: 'aggressive', blockScripts: true });
  assert.deepEqual(eff['example.com'], { mode: 'aggressive' });
  assert.deepEqual(eff['other.ch'], { mode: 'standard' });
  assert.equal(resolveSite('www.shop.example.com', eff, defaultSettings()).mode, 'aggressive');
  // The user's own data is untouched (removing the policy restores it).
  assert.equal(user['shop.example.com'].mode, 'standard');
  assert.equal(coveredBy('a.shop.example.com', new Set(['example.com'])), true);
  assert.equal(coveredBy('example.org', new Set(['example.com'])), false);
});

test('keepPolicyOwnedFields: a policy overlay never becomes user data (SW-2)', () => {
  const managed = { disabledSites: ['crm.example.ch'], aggressiveSites: ['news.example.com'] };
  const prev = { 'shop.example.org': { blockScripts: true } };
  // What an old dashboard sent back: the effective map with the overlays copied in.
  const sent = {
    'crm.example.ch': { enabled: false },
    'news.example.com': { mode: 'aggressive' as const, fingerprinting: 'strict' as const },
    'shop.example.org': { blockScripts: false },
  };
  const next = keepPolicyOwnedFields(sent, prev, managed);
  assert.deepEqual(next, { 'news.example.com': { fingerprinting: 'strict' }, 'shop.example.org': { blockScripts: false } });
  // The user's own value of a policy-owned field is kept, even if the row is gone.
  const kept = keepPolicyOwnedFields({}, { 'crm.example.ch': { enabled: true } }, managed);
  assert.deepEqual(kept, { 'crm.example.ch': { enabled: true } });
  // allowUserSiteToggle=false: `enabled` of every host stays as it was.
  const locked = keepPolicyOwnedFields({ 'a.ch': { enabled: false }, 'b.ch': { mode: 'standard' } }, { 'b.ch': { enabled: true } }, { allowUserSiteToggle: false });
  assert.deepEqual(locked, { 'b.ch': { mode: 'standard', enabled: true } });
});

test('effectiveSites: disabledSites wins on subdomains too', () => {
  const managed = { disabledSites: ['crm.example.ch'] };
  const eff = effectiveSites({ 'portal.crm.example.ch': { enabled: true, blockScripts: true }, 'app.crm.example.ch': { enabled: true } }, managed);
  assert.deepEqual(eff, { 'crm.example.ch': { enabled: false }, 'portal.crm.example.ch': { blockScripts: true } });
  assert.equal(resolveSite('portal.crm.example.ch', eff, defaultSettings()).enabled, false);
  assert.equal(resolveSite('app.crm.example.ch', eff, defaultSettings()).enabled, false);
  // An unrelated user re-enable is untouched.
  const other = effectiveSites({ 'example.com': { enabled: false }, 'shop.example.com': { enabled: true } }, managed);
  assert.deepEqual(other['shop.example.com'], { enabled: true });
});
