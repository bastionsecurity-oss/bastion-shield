// Cosmetic filter tests: kinds, exceptions, entities, generic token
// extraction, selector validation and unsupported syntaxes (ARCHITECTURE §5.1).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { compileList } from '../../src/compiler/index.ts';
import type { CompiledList } from '../../src/compiler/types.ts';
import { opts, rulesOf } from './helpers.ts';

const compile = (text: string): CompiledList => compileList(text, opts());
const reasons = (text: string): string[] => compile(text).stats.rejected.map((r) => r.reason);

describe('specific filters', () => {
  test('hide selector (kind 0) with included and excluded hosts', () => {
    assert.deepEqual(compile('example.com,~sub.example.com##.ad').specific, [
      { kind: 0, hosts: ['example.com'], excludedHosts: ['sub.example.com'], payload: '.ad', raw: 'example.com,~sub.example.com##.ad' },
    ]);
  });
  test('hostnames are normalized (lower case, punycode, trailing dot)', () => {
    assert.deepEqual(compile('Example.COM.,bücher.de##.ad').specific[0].hosts, ['example.com', 'xn--bcher-kva.de']);
  });
  test('entities are kept as hostKeys', () => {
    assert.deepEqual(compile('google.*,www.amazon.*##.ad').specific[0].hosts, ['google.*', 'www.amazon.*']);
  });
  test('invalid hostnames reject the filter', () => {
    assert.deepEqual(reasons('exa mple.com##.ad'), ['invalid-domain']);
    assert.deepEqual(reasons('a.com,,b.com##.ad'), ['invalid-domain']);
  });
  test('regex / path host forms are not supported for cosmetic filters', () => {
    assert.deepEqual(reasons('/^www\\.example\\.[a-z]+$/##.ad'), ['unsupported-domain-syntax']);
    const out = compile('a.com,b.com/path##.ad');
    assert.deepEqual(out.specific[0].hosts, ['a.com']);
    assert.equal(out.stats.reasons['warn:cosmetic-host-syntax-dropped'], 1);
  });
  test('exception (kind 1) ignores negated hosts', () => {
    assert.deepEqual(compile('a.com,~b.a.com#@#.ad').specific, [{ kind: 1, hosts: ['a.com'], excludedHosts: [], payload: '.ad', raw: 'a.com,~b.a.com#@#.ad' }]);
  });
  test('whitespace and combinators are canonicalized so exceptions match', () => {
    const out = compile('a.com##div>p  .x\na.com#@#div > p .x');
    assert.equal(out.specific[0].payload, 'div > p .x');
    assert.equal(out.specific[1].payload, 'div > p .x');
  });
  test(':style() -> kind 3 CSS rule text', () => {
    assert.deepEqual(compile('a.com##.x:style(color: red !important)').specific[0], {
      kind: 3, hosts: ['a.com'], excludedHosts: [], payload: '.x { color: red !important }', raw: 'a.com##.x:style(color: red !important)',
    });
  });
  test('AdGuard/EasyList "sel { style }" injection maps to :style()', () => {
    assert.equal(compile('a.com##.x { margin: 0 }').specific[0].payload, '.x { margin: 0 }');
    assert.deepEqual(compile('a.com##.x { display: none !important; }').specific[0].kind, 0);
  });
  test(':style() rejects url(), comments and braces', () => {
    for (const f of ['a.com##.x:style(background: url(http://x))', 'a.com##.x:style(color: red /* x */)', 'a.com##.x:style(}body{color:red)']) {
      assert.equal(compile(f).specific.length, 0, f);
    }
  });
  test('procedural selector -> kind 2 JSON', () => {
    const s = compile('a.com##div.ad:has-text(/Sponsored/i)').specific[0];
    assert.equal(s.kind, 2);
    assert.deepEqual(JSON.parse(s.payload), { raw: 'div.ad:has-text(/Sponsored/i)', selector: 'div.ad', tasks: [['has-text', '/Sponsored/i']] });
  });
  test('procedural exception -> kind 5 with the raw selector', () => {
    assert.deepEqual(compile('a.com#@#div.ad:has-text(Ad)').specific[0], {
      kind: 5, hosts: ['a.com'], excludedHosts: [], payload: 'div.ad:has-text(Ad)', raw: 'a.com#@#div.ad:has-text(Ad)',
    });
  });
  test('#?# with plain CSS (and ABP :-abp-has) stays native CSS', () => {
    assert.deepEqual(compile('a.com#?#div:-abp-has(> .sponsor)').specific[0].payload, 'div:has(> .sponsor)');
    assert.equal(compile('a.com#?#.ad').specific[0].kind, 0);
  });
  test(':-abp-* operators need #?#', () => {
    assert.deepEqual(reasons('a.com##div:-abp-has(.x)'), ['invalid-selector:unsupported-pseudo']);
  });
  test('$generichide-style flags are not produced by cosmetic syntax', () => {
    assert.equal(compile('a.com##.x').specific.every((s) => s.kind !== 4), true);
  });
});

describe('generic filters', () => {
  test('lowly generic selectors are keyed by a required #id / .class token', () => {
    const g = compile('##.ad-banner\n###ad_box\n##div.sponsor > img\n##[data-ad] .ad-slot\n##a[href*="ads"]').generic;
    assert.deepEqual(g.map((x) => [x.selector, x.token]), [
      ['.ad-banner', '.ad-banner'],
      ['#ad_box', '#ad_box'],
      ['div.sponsor > img', '.sponsor'],
      ['[data-ad] .ad-slot', '.ad-slot'],
      ['a[href*="ads"]', null],
    ]);
  });
  test('tokens inside :not() / :is() are never used as keys', () => {
    assert.deepEqual(compile('##div:not(.content)').generic[0].token, null);
    assert.deepEqual(compile('##div:is(.a, .b)').generic[0].token, null);
  });
  test('escaped identifiers are decoded in the key', () => {
    assert.deepEqual(compile('##.md\\:hidden').generic[0].token, '.md:hidden');
  });
  test('selector lists are split into separate generic entries', () => {
    assert.deepEqual(compile('##.a, #b').generic.map((x) => [x.selector, x.token]), [['.a', '.a'], ['#b', '#b']]);
  });
  test('only-negated hosts make a generic filter with exclusions', () => {
    assert.deepEqual(compile('~a.com,~b.com##.ad').generic, [{ selector: '.ad', token: '.ad', excludedHosts: ['a.com', 'b.com'], raw: '~a.com,~b.com##.ad' }]);
  });
  test('"*" host means generic', () => {
    assert.equal(compile('*##.ad').generic.length, 1);
  });
  test('generic exceptions (#@#sel) are listed for build-time removal', () => {
    assert.deepEqual(compile('#@#.ad\n#@#.a, .b').genericExceptions, ['.ad', '.a', '.b']);
  });
  test('generic procedural / style filters are not supported', () => {
    assert.deepEqual(reasons('##div:has-text(Ad)'), ['unsupported:generic-procedural']);
    assert.deepEqual(reasons('##.x:style(color: red)'), ['unsupported:generic-procedural']);
  });
  test('one-character generic selectors are dropped', () => {
    assert.deepEqual(reasons('##*'), ['invalid-selector:too-generic']);
  });
});

describe('selector validation', () => {
  const valid = [
    '##.ad', '##div[id^="ad-"]', '##a[href*=ads i]', '##.x::before', '##.x:nth-child(2n+1)', '##.x:nth-child(odd of .y)',
    '##div:has(> img.ad)', '##div:not(.a):not(.b)', '##.x::-webkit-scrollbar', '##ins.adsbygoogle[data-ad-slot]',
    '##[class*="sponsor" s]', '##div:where(.a, .b) > .c', '##.x:has(+ .y)',
  ];
  for (const f of valid) test(`valid: ${f}`, () => assert.equal(compile(f).generic.length, 1, f));
  const invalid = [
    '##.x {', '##.x}', '##div[id', '##div[id="x]', '##.x:unknown-pseudo', '##.x:-moz-any(.a)', '##> .x', '##.x >',
    '##.x:has(.y:has(.z))', '##.x:has(::before)', '##.1abc', '##div:not()', '##[data-ad=1]', '##.x:nth-child(foo)',
    '##.x,', '##.x::unknown',
  ];
  for (const f of invalid) {
    test(`invalid: ${f}`, () => {
      const out = compile(f);
      assert.equal(out.generic.length + out.specific.length, 0, f);
      assert.equal(out.stats.unsupported, 1, f);
    });
  }
});

describe('unsupported cosmetic syntaxes', () => {
  test('AdGuard and ABP snippet separators', () => {
    assert.deepEqual(reasons('a.com#$#.ad { display: none }'), ['unsupported:adguard-css-injection']);
    assert.deepEqual(reasons('a.com#$#abort-on-property-read foo'), ['unsupported:abp-snippet']);
    assert.deepEqual(reasons('a.com#@$#.ad { display: none }'), ['unsupported:adguard-css-injection']);
    assert.deepEqual(reasons("a.com#%#//scriptlet('set-constant', 'x', '1')"), ['unsupported:adguard-scriptlet']);
  });
  test('HTML filtering', () => {
    assert.deepEqual(reasons('a.com##^script:has-text(ads)'), ['unsupported:html-filtering']);
  });
});

describe('##^responseheader()', () => {
  test('removes the header on the listed sites (modifyHeaders, priority 1)', () => {
    const rules = rulesOf(compile('a.com,b.com##^responseheader(Set-Cookie)'));
    const mf = rules.find((r) => r.condition.resourceTypes?.join() === 'main_frame');
    const sf = rules.find((r) => r.condition.resourceTypes?.join() === 'sub_frame');
    assert.deepEqual(mf, {
      priority: 1,
      action: { type: 'modifyHeaders', responseHeaders: [{ header: 'set-cookie', operation: 'remove' }] },
      condition: { resourceTypes: ['main_frame'], requestDomains: ['a.com', 'b.com'] },
    });
    assert.deepEqual(sf?.condition.initiatorDomains, ['a.com', 'b.com']);
  });
  test('only uBO-removable headers, no exceptions, no generic form', () => {
    assert.deepEqual(reasons('a.com##^responseheader(content-security-policy)'), ['unsupported:responseheader-name']);
    assert.deepEqual(reasons('a.com#@#^responseheader(location)'), ['unsupported:responseheader-exception']);
    assert.deepEqual(reasons('##^responseheader(location)'), ['unsupported:generic-responseheader']);
  });
});

describe('line handling', () => {
  test('comments and headers are skipped', () => {
    const out = compile('[Adblock Plus 2.0]\n! Title: x\n# hosts comment\n####\n##.ad');
    assert.equal(out.stats.filters, 1);
  });
  test('uBO line continuation joins indented lines', () => {
    const out = compile('example.com##+js(set, \\\n    foo, 1)');
    assert.deepEqual(out.scriptlets[0].args, ['foo', '1']);
  });
});
