// restrictRedirectCopies(): keep the third-party copies of protected-list
// redirects only where an always-apply block can meet them (BS-1).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { compileList, isRedirectCopy, restrictRedirectCopies } from '../../src/compiler/index.ts';
import type { CompiledList, DnrRule } from '../../src/compiler/types.ts';
import { urlFilterToRegExp } from '../../src/compiler/copies.ts';
import { opts, rulesOf } from './helpers.ts';

function lists(protectedText: string, alwaysText: string): { prot: CompiledList; always: CompiledList } {
  return {
    prot: compileList(protectedText, opts({ listId: 'prot', firstPartyProtected: true })),
    always: compileList(alwaysText, opts({ listId: 'always', firstPartyProtected: false })),
  };
}

/** Run the pass and return the protected list's redirect rules as [priority, domainType]. */
function restrict(protectedText: string, alwaysText: string): { kept: [number | undefined, string | undefined][]; stats: { copies: number; kept: number } } {
  const { prot, always } = lists(protectedText, alwaysText);
  const stats = restrictRedirectCopies([
    { firstPartyProtected: true, compiled: prot },
    { firstPartyProtected: false, compiled: always },
  ]);
  const kept = rulesOf(prot).filter((r) => r.action.type === 'redirect').map((r): [number | undefined, string | undefined] => [r.priority, r.condition.domainType]);
  return { kept, stats };
}

const KEPT: [number, string | undefined][] = [[16, undefined], [27, 'thirdParty']];
const DROPPED: [number, string | undefined][] = [[16, undefined]];
const OUTBRAIN = '||widgets.outbrain.com/outbrain.js$script,redirect=noop.js:5,domain=~vice.com';

describe('restrictRedirectCopies', () => {
  test('keeps the outbrain copy that an always-apply "/outbrain.js" block would otherwise beat', () => {
    const r = restrict(OUTBRAIN, '/outbrain.js');
    assert.deepEqual(r.kept, KEPT);
    assert.deepEqual(r.stats, { copies: 1, kept: 1 });
  });
  test('drops copies no always-apply block can meet, keeping the original', () => {
    const r = restrict(OUTBRAIN, '||other.example^\n/banner.js');
    assert.deepEqual(r.kept, DROPPED);
    assert.deepEqual(r.stats, { copies: 1, kept: 0 });
  });
  test('host blocks: same host, parent host, subdomain', () => {
    const fc = '||fundingchoicesmessages.google.com/i/pub$script,redirect=noopjs:5,domain=doctoraux.com';
    assert.deepEqual(restrict(fc, '||fundingchoicesmessages.google.com^').kept, KEPT);
    assert.deepEqual(restrict(fc, '||google.com^$script').kept, KEPT);
    // A redirect path is not grafted onto a deeper block host (buttons.googlesyndication.com
    // would otherwise keep every `||googlesyndication.com/…` redirect copy).
    assert.deepEqual(restrict('||outbrain.com/x.js$script,redirect=noop.js:5', '||cdn.outbrain.com^').kept, DROPPED);
    assert.deepEqual(restrict('||outbrain.com^$script,redirect=noop.js:5', '||cdn.outbrain.com^').kept, KEPT);
    assert.deepEqual(restrict(fc, '||googlesyndication.com^').kept, DROPPED);
  });
  test('URL pattern blocks match a sample URL of the redirect, and the reverse', () => {
    const ads = '||adservice.google.com/adsid/integrator.js$script,redirect=noopjs:5,domain=tubia.com';
    assert.deepEqual(restrict(ads, '/adservice.').kept, KEPT);
    assert.deepEqual(restrict(ads, '/adsid/integrator.$script').kept, KEPT);
    assert.deepEqual(restrict(ads, '/adsid/other.').kept, DROPPED);
    // A redirect broader than the block: the block's own URL is tried on the redirect.
    assert.deepEqual(restrict('||outbrain.com^$script,redirect=noop.js:5', '||widgets.outbrain.com/outbrain.js').kept, KEPT);
    assert.deepEqual(restrict('/prebid/*$script,redirect=noop.js:5', '||cdn.example/prebid/prebid.js').kept, KEPT);
    // Generic block paths are not grafted onto the redirect's host, nor redirect paths onto block hosts.
    assert.deepEqual(restrict('||al5sm.com^$script,redirect=noop.js:5', '/ads/loader.'), { kept: DROPPED, stats: { copies: 1, kept: 0 } });
    assert.deepEqual(restrict('/prebid.js$script,redirect=noop.js:5', '||ads.example^').kept, DROPPED);
    // Without any URL pattern, a type/initiator redirect meets every block of that type.
    assert.deepEqual(restrict('*$media,redirect=noop.js:5,domain=tv.example', '||ads.example^').kept, KEPT);
  });
  test('a site-specific block only meets redirects limited to that site', () => {
    assert.deepEqual(restrict(OUTBRAIN, '*$script,3p,domain=one-site.example').kept, DROPPED);
    assert.deepEqual(restrict('/w.js$script,redirect=noop.js:5,domain=one-site.example', '*$script,3p,domain=one-site.example').kept, KEPT);
  });
  test('regex blocks are tested against the sample URL', () => {
    assert.deepEqual(restrict(OUTBRAIN, '/^https:\\/\\/widgets\\.[a-z]+\\.com\\/[a-z]+\\.js/$script').kept, KEPT);
    assert.deepEqual(restrict(OUTBRAIN, '/^https:\\/\\/cdn\\.[a-z]+\\.com\\//$script').kept, DROPPED);
  });
  test('types, party and methods must meet', () => {
    assert.deepEqual(restrict(OUTBRAIN, '||widgets.outbrain.com^$image').kept, DROPPED);
    assert.deepEqual(restrict(OUTBRAIN, '/outbrain.js$1p').kept, DROPPED);
    assert.deepEqual(restrict(OUTBRAIN, '/outbrain.js$3p').kept, KEPT);
    assert.deepEqual(restrict(OUTBRAIN, '/outbrain.js$~script').kept, DROPPED);
    assert.deepEqual(restrict('/x.js$script,method=get,redirect=noop.js:5', '/x.js$method=post').kept, DROPPED);
  });
  test('initiator domains and exclusions', () => {
    const red = '/w.js$script,redirect=noop.js:5,domain=sub.a.example';
    assert.deepEqual(restrict(red, '/w.js$domain=a.example').kept, KEPT);
    assert.deepEqual(restrict(red, '/w.js$domain=b.example').kept, DROPPED);
    assert.deepEqual(restrict(red, '/w.js$domain=~a.example').kept, DROPPED);
    assert.deepEqual(restrict(red, '/w.js$domain=~other.sub.a.example').kept, KEPT);
    assert.deepEqual(restrict('/w.js$script,redirect=noop.js:5,domain=~b.example', '/w.js$domain=b.example').kept, DROPPED);
  });
  test('only BLOCK_ALWAYS rules count: exceptions, redirects, modifiers and $important do not', () => {
    for (const always of ['@@/outbrain.js', '/outbrain.js$script,redirect=noop.js', '/outbrain.js$removeparam=x', '/outbrain.js$important']) {
      assert.deepEqual(restrict(OUTBRAIN, always).kept, DROPPED, always);
    }
  });
  test('blocks from protected lists do not keep copies; other rules are untouched', () => {
    const prot = compileList(`${OUTBRAIN}\n/outbrain.js\n||x.example^`, opts({ firstPartyProtected: true }));
    const before = rulesOf(prot).filter((r) => !isRedirectCopy(r));
    const stats = restrictRedirectCopies([{ firstPartyProtected: true, compiled: prot }]);
    assert.deepEqual(stats, { copies: 1, kept: 0 });
    assert.deepEqual(rulesOf(prot), before);
  });
  test('always-apply lists keep their own redirects in the same band', () => {
    const always = compileList('/x.js$script,3p,redirect=noop.js', opts({ firstPartyProtected: false }));
    const stats = restrictRedirectCopies([{ firstPartyProtected: false, compiled: always }]);
    assert.deepEqual(stats, { copies: 0, kept: 0 });
    assert.equal(rulesOf(always).length, 1);
  });
  test('isRedirectCopy recognises only the third-party copy band', () => {
    const rules: DnrRule[] = rulesOf(compileList('/a.js$script,redirect=noop.js\n/b.js$script,redirect=noop.js,important', opts()));
    assert.deepEqual(rules.map(isRedirectCopy), [false, true, false]);
  });
});

describe('urlFilterToRegExp', () => {
  test('anchors, wildcards and separators follow DNR', () => {
    const t = (uf: string, url: string): boolean => urlFilterToRegExp(uf).test(url);
    assert.ok(t('||ads.example^', 'https://cdn.ads.example/x'));
    assert.ok(!t('||ads.example^', 'https://bads.example/x'));
    assert.ok(t('||ads.example^', 'https://ads.example'));
    assert.ok(t('|https://a.example/x|', 'https://a.example/x'));
    assert.ok(!t('|https://a.example/x|', 'https://a.example/xy'));
    assert.ok(t('/ad*.js', 'https://h.example/ad-loader.js'));
    assert.ok(t('/AD.js', 'https://h.example/ad.js'));
    assert.ok(!urlFilterToRegExp('/AD.js', '').test('https://h.example/ad.js'));
    assert.ok(!t('ad^', 'https://h.example/ad.js'));
    assert.ok(t('ad^', 'https://h.example/ad?x'));
  });
});
