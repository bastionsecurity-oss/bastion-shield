// Tests for the build helpers: DNR rule validation, the bastion-params
// ruleset, CSS selector checks, version numbers, cosmetic data output,
// ruleset finalization (ids + transparency maps) and manifest order.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CompiledList, CompiledRule, DnrRule } from '../../src/compiler/types.ts';
import type { CatalogList, CosmeticMeta, CosmeticShard, GenericIndex } from '../../src/shared/types.ts';
import { PRIORITY } from '../../src/shared/constants.ts';
import { shardName, shardOf } from '../../src/shared/hash.ts';
import { sanitizeRule, orderRule } from '../../tools/lib/dnr.ts';
import { buildParamsRuleset, type QueryFilterEntry } from '../../tools/lib/params.ts';
import { hideRules, selectorProblem } from '../../tools/lib/css.ts';
import { baseVersion, buildNumber, daysSinceEpoch } from '../../tools/lib/version.ts';
import { writeCosmetic } from '../../tools/lib/cosmetic.ts';
import { createLogger, readJson, ROOT } from '../../tools/lib/util.ts';
import { finalizeRuleset, hostsToAbp, rulesetOrder } from '../../tools/build.ts';
import { loadResources } from '../../tools/resources.ts';
import { genericLookupFromText } from '../../src/background/cosmetic.ts';

const block = (condition: DnrRule['condition'], extra: Partial<DnrRule> = {}): DnrRule => ({ priority: 10, action: { type: 'block' }, condition, ...extra });

test('sanitizeRule accepts and normalizes valid rules', () => {
  const r = sanitizeRule(block({ requestDomains: ['B.com', 'a.com', 'a.com'], resourceTypes: ['script', 'image'] }), { allowRegex: false });
  assert.equal(r.error, undefined);
  assert.deepEqual(r.rule!.condition.requestDomains, ['a.com', 'b.com']);
  assert.deepEqual(r.rule!.condition.resourceTypes, ['image', 'script']);
  const ex = sanitizeRule(block({ urlFilter: '||x.com^', excludedInitiatorDomains: [] }), { allowRegex: false });
  assert.equal(ex.rule!.condition.excludedInitiatorDomains, undefined, 'empty exclusion lists are dropped');
  const t = sanitizeRule({ action: { type: 'redirect', redirect: { transform: { query: '' } } }, condition: { urlFilter: '^utm_' } }, { allowRegex: false });
  assert.equal(t.error, undefined, 'empty query (strip all) is valid');
});

test('sanitizeRule rejects what Chromium rejects', () => {
  const bad: [DnrRule, string, boolean?][] = [
    [block({ requestDomains: [] }), 'empty requestDomains'],
    [block({ resourceTypes: [] }), 'empty resourceTypes'],
    [block({ urlFilter: '||*foo' }), '||*'],
    [block({ urlFilter: 'é' }), 'non-ASCII urlFilter'],
    [block({ urlFilter: 'a', regexFilter: 'b' }), 'both specified', true],
    [block({ regexFilter: 'a(?=b)' }), 'lookaround', true],
    [block({ regexFilter: '(a)\\1' }), 'backreference', true],
    [block({ regexFilter: 'abc' }), 'non-regex ruleset', false],
    [block({ resourceTypes: ['script'], excludedResourceTypes: ['script'] }), 'both included and excluded'],
    [block({ resourceTypes: ['scripts'] }), 'invalid resource type'],
    [block({ tabIds: [1] }), 'session rules'],
    [block({ initiatorDomains: ['ä.com'] }), 'non-ASCII domain'],
    [{ action: { type: 'allowAllRequests' }, condition: { requestDomains: ['a.com'] } }, 'allowAllRequests'],
    [{ action: { type: 'redirect', redirect: { extensionPath: 'war/noop.js' } }, condition: {} }, 'start with "/"'],
    [{ action: { type: 'redirect', redirect: { transform: { query: 'a=1' } } }, condition: {} }, 'start with "?"'],
    [{ action: { type: 'redirect', redirect: { url: 'javascript:alert(1)' } }, condition: {} }, 'javascript: redirect'],
    [{ action: { type: 'redirect', redirect: { url: 'data:text/html,x' } }, condition: {} }, 'data: redirect'],
    [{ action: { type: 'redirect', redirect: { url: 'vbscript:x' } }, condition: {} }, 'vbscript: redirect'],
    [{ action: { type: 'redirect', redirect: { regexSubstitution: '\\1' } }, condition: { urlFilter: 'x' } }, 'regexSubstitution without regexFilter'],
    [{ action: { type: 'modifyHeaders', requestHeaders: [{ header: 'X-A', operation: 'append', value: '1' }] }, condition: {} }, 'append not allowed'],
    [{ action: { type: 'modifyHeaders', responseHeaders: [{ header: 'x', operation: 'remove', value: '1' }] }, condition: {} }, 'remove operation with a value'],
    [{ action: { type: 'modifyHeaders' }, condition: {} }, 'without headers'],
    [block({}, { priority: 0 }), 'invalid priority'],
  ];
  for (const [rule, reason, allowRegex] of bad) {
    const r = sanitizeRule(rule, { allowRegex: allowRegex ?? true });
    assert.ok(r.error?.includes(reason), `${JSON.stringify(rule)} -> ${r.error} (expected "${reason}")`);
  }
});

test('orderRule omits the default priority 1 and orders keys', () => {
  assert.deepEqual(Object.keys(orderRule({ id: 3, priority: 1, action: { type: 'block' }, condition: {} })), ['id', 'action', 'condition']);
  assert.deepEqual(Object.keys(orderRule({ id: 3, priority: 10, action: { type: 'block' }, condition: {} })), ['id', 'priority', 'action', 'condition']);
});

test('bastion-params from the vendored Brave query-filter.json', async () => {
  const entries = await readJson<QueryFilterEntry[]>(join(ROOT, 'vendor', 'brave-lists', 'query-filter.json'));
  const { rules, sources, warnings } = buildParamsRuleset(entries);
  assert.deepEqual(warnings, []);
  assert.equal(rules.length, sources.length);
  const strip = rules.filter((r) => r.action.type === 'redirect');
  const fbclid = strip.find((r) => r.action.redirect?.transform?.queryTransform?.removeParams?.[0] === 'fbclid')!;
  assert.equal(fbclid.priority, PRIORITY.PARAMS);
  assert.equal(fbclid.condition.urlFilter, '^fbclid=');
  assert.equal(fbclid.condition.domainType, 'thirdParty');
  assert.deepEqual(fbclid.condition.resourceTypes, ['main_frame', 'sub_frame']);
  assert.deepEqual(fbclid.condition.requestMethods, ['get']);
  assert.deepEqual(fbclid.condition.excludedRequestDomains, ['urldefense.com']);
  assert.equal(fbclid.condition.requestDomains, undefined);
  const si = strip.find((r) => r.action.redirect?.transform?.queryTransform?.removeParams?.[0] === 'si')!;
  assert.deepEqual(si.condition.requestDomains, ['youtu.be', 'youtube.com']);
  const igsh = strip.find((r) => r.action.redirect?.transform?.queryTransform?.removeParams?.[0] === 'igsh')!;
  assert.deepEqual(igsh.condition.requestDomains, ['instagram.com']);
  // One rule per parameter: every global param of the JSON appears exactly once.
  const globalParams = entries.find((e) => e.include.includes('*://*/*'))!.params;
  for (const p of globalParams) assert.equal(strip.filter((r) => r.action.redirect?.transform?.queryTransform?.removeParams?.[0] === p && !r.condition.requestDomains).length, 1, p);
  // brave-core conditional params: stripped unless the URL contains the marker.
  assert.ok(strip.some((r) => r.condition.urlFilter === '^mkt_tok='));
  const allows = rules.filter((r) => r.action.type === 'allow');
  assert.ok(allows.some((r) => r.condition.urlFilter === 'unsubscribe*^mkt_tok='));
  for (const r of rules) assert.equal(sanitizeRule(r, { allowRegex: false }).error, undefined, JSON.stringify(r));
});

test('selectorProblem', () => {
  for (const ok of ['.ad', '#x > .y', 'div[class^="ad-"]', 'a[href*=":"]', '.md\\:block', 'div:has(> .ad)', 'p:not(.a):nth-child(2n+1)', 'div::before', 'input::-webkit-input-placeholder', 'ins.adsbygoogle[data-ad-status="unfilled"]']) {
    assert.equal(selectorProblem(ok), null, ok);
  }
  for (const [bad, why] of [
    ['div:has-text(Ad)', 'unknown pseudo'],
    ['div:-abp-has(.x)', 'procedural'],
    ['.a{color:red}', 'unexpected'],
    ['div[class="x]', 'unterminated'],
    ['div(', 'unbalanced'],
    ['> .x', 'leading combinator'],
    ['.x >', 'trailing combinator'],
    ['', 'empty'],
  ] as const) {
    assert.ok(selectorProblem(bad)?.includes(why), `${bad} -> ${selectorProblem(bad)}`);
  }
  assert.equal(hideRules(['.a', '.b', '.c'], 2), '.a,\n.b{display:none!important}\n.c{display:none!important}\n');
});

test('version numbers', () => {
  assert.equal(daysSinceEpoch(new Date('2026-01-01T23:59:00Z')), 0);
  assert.equal(buildNumber(new Date('2026-10-18T08:00:00Z'), 0), 2900);
  assert.equal(buildNumber(new Date('2026-10-18T08:00:00Z'), 3), 2903);
  assert.throws(() => buildNumber(new Date('2026-10-18T08:00:00Z'), 10), /0\.\.9/);
  assert.equal(baseVersion('0.1.0'), '0.1.0');
  assert.equal(baseVersion('1.2.3-beta.1'), '1.2.3');
  assert.throws(() => baseVersion('1.2'), /MAJOR/);
});

test('hostsToAbp', () => {
  assert.equal(hostsToAbp('# c\n0.0.0.0 a.example\n127.0.0.1 B.example # x\nlocalhost\nbare.example\n'), '||a.example^\n||b.example^\n||bare.example^');
});

test('rulesetOrder follows ARCHITECTURE §4.1', () => {
  const mk = (id: string, category: CatalogList['category']) => ({ id, category }) as CatalogList;
  const lists = [mk('cookies', 'annoyances'), mk('regional-de', 'regional'), mk('easylist', 'ads'), mk('url-tracking', 'privacy'), mk('ublock', 'ads'), mk('urlhaus', 'security'), mk('bastion', 'ads'), mk('peter-lowe', 'privacy')];
  assert.deepEqual(rulesetOrder(lists).map((l) => l.id), ['bastion', 'urlhaus', 'ublock', 'easylist', 'peter-lowe', 'url-tracking', 'regional-de', 'cookies']);
});

test('finalizeRuleset: dense ids, merged duplicates, transparency map, dropped invalid rules', async () => {
  const resources = await loadResources(createLogger('t', true));
  const cr = (rule: DnrRule, sources: string[], sourceCount = sources.length): CompiledRule => ({ rule, sources, sourceCount });
  const out = finalizeRuleset('x', 'x', [
    cr(block({ urlFilter: '||a.com^' }), ['||a.com^']),
    cr(block({ requestDomains: [] }), ['bad']),
    cr(block({ urlFilter: '||a.com^' }), ['||a.com^$script'], 1),
    cr({ action: { type: 'redirect', redirect: { extensionPath: '/war/noop.js' } }, condition: { urlFilter: 'x.js' } }, ['x.js$redirect=noop.js']),
    cr({ action: { type: 'redirect', redirect: { extensionPath: '/war/does-not-exist.js' } }, condition: { urlFilter: 'y.js' } }, ['y']),
    cr(block({ requestDomains: Array.from({ length: 30 }, (_, i) => `h${i}.com`) }), Array.from({ length: 20 }, (_, i) => `||h${i}.com^`), 30),
  ], false, resources);
  assert.deepEqual(out.rules.map((r) => r.id), [1, 2, 3]);
  assert.equal(out.sources[0], null);
  assert.deepEqual(out.sources[1], ['||a.com^', '||a.com^$script']);
  assert.equal(out.sources[3]!.length, 21);
  assert.equal(out.sources[3]![20], '+10 more');
  assert.equal(out.invalid['empty requestDomains'], 1);
  assert.equal(out.invalid['redirect target /war/does-not-exist.js is not shipped'], 1);
  assert.deepEqual([...out.redirectPaths], ['/war/noop.js']);
});

test('writeCosmetic: shards, masks, exclusions, generic index, highly generic CSS', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bastion-cos-'));
  try {
    const base = (): Pick<CompiledList, 'specific' | 'generic' | 'genericExceptions' | 'generichideHosts' | 'specifichideHosts'> => ({
      specific: [],
      generic: [],
      genericExceptions: [],
      generichideHosts: [],
      specifichideHosts: [],
    });
    const a = base();
    a.specific.push({ kind: 0, hosts: ['example.com', 'google.*'], excludedHosts: ['sub.example.com'], payload: '.ad', raw: 'example.com,google.*,~sub.example.com##.ad' });
    a.specific.push({ kind: 0, hosts: ['example.com'], excludedHosts: [], payload: 'div:has-text(x)', raw: 'bad' });
    a.generic.push({ selector: '.banner-ad', token: '.banner-ad', excludedHosts: [], raw: '##.banner-ad' });
    a.generic.push({ selector: 'div[id^="ad-"]', token: null, excludedHosts: ['news.example'], raw: '~news.example##div[id^="ad-"]' });
    a.generic.push({ selector: '.gone', token: '.gone', excludedHosts: [], raw: '##.gone' });
    a.generichideHosts.push('nogeneric.example');
    const b = base();
    b.specific.push({ kind: 0, hosts: ['example.com'], excludedHosts: [], payload: '.ad', raw: 'example.com##.ad' });
    b.specific.push({ kind: 1, hosts: ['exc.example'], excludedHosts: [], payload: 'div[id^="ad-"]', raw: 'exc.example#@#div[id^="ad-"]' });
    b.generic.push({ selector: '.banner-ad', token: '.banner-ad', excludedHosts: [], raw: '##.banner-ad' });
    b.genericExceptions.push('.gone');
    const res = await writeCosmetic(dir, [
      { listId: 'a', bit: 0, compiled: a },
      { listId: 'b', bit: 31, compiled: b },
    ], createLogger('t', true));

    const shardFor = async (host: string) => readJson<CosmeticShard>(join(dir, 'cosmetic', 'specific', `${shardName(shardOf(host))}.json`));
    const ex = (await shardFor('example.com')).hosts['example.com'];
    assert.deepEqual(ex, [[0, '.ad', 2147483649]], 'same entry from two lists merges masks (bit 0 | bit 31)');
    assert.deepEqual((await shardFor('google.*')).hosts['google.*'], [[0, '.ad', 1]]);
    assert.deepEqual((await shardFor('sub.example.com')).hosts['sub.example.com'], [[1, '.ad', 1]], '~host -> exception entry');
    assert.deepEqual((await shardFor('nogeneric.example')).hosts['nogeneric.example'], [[4, 'generichide', 1]]);
    assert.equal(res.perList.a.rejected['css: unknown pseudo :has-text'], 1);

    const gi = await readJson<GenericIndex>(join(dir, 'cosmetic', 'generic.json'));
    assert.deepEqual(gi.tokens['.banner-ad'], [['.banner-ad', 2147483649]]);
    assert.equal(gi.tokens['.gone'], undefined, 'generic #@# exception removes the selector');
    // One sorted token per line: the service worker searches the text in place (PERF-5).
    const giText = await readFile(join(dir, 'cosmetic', 'generic.json'), 'utf8');
    assert.match(giText, /^\{"tokens":\{\n"\.banner-ad":\[\["\.banner-ad",2147483649\]\]\n\}\}\n$/);
    assert.deepEqual(genericLookupFromText(giText)?.get('.banner-ad'), [['.banner-ad', 2147483649]]);

    const meta = await readJson<CosmeticMeta>(join(dir, 'cosmetic', 'meta.json'));
    assert.equal(meta.shards, 256);
    assert.equal(meta.genericHighCss.a, 'cosmetic/generic-high/a.css');
    assert.equal(meta.genericHighCss.b, null);
    // List-specific exclusions per list; generichide hosts once for all lists.
    assert.deepEqual(meta.genericHighExcludedHosts.a, ['exc.example', 'news.example']);
    assert.deepEqual(meta.genericHideHosts, ['nogeneric.example']);
    assert.equal(await readFile(join(dir, 'cosmetic', 'generic-high', 'a.css'), 'utf8'), 'div[id^="ad-"]{display:none!important}\n');
    const high = await readJson<Record<string, string[]>>(join(dir, 'cosmetic', 'generic-high.json'));
    assert.deepEqual(high, { a: ['div[id^="ad-"]'], b: [] });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
