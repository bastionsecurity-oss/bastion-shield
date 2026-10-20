// Tests for the Lab's explain mode (src/ui/dashboard/lab-explain.ts): the
// cheap pre-checks, page-level allowAllRequests, the winner across sources
// and the streaming runner with fake rulesets, custom and dynamic rules.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PRIORITY, RULE_ID } from '../../src/shared/constants.ts';
import { prepareRequest, type MatchRule } from '../../src/shared/dnr-match.ts';
import type { DryRequest } from '../../src/ui/dashboard/lab-core.ts';
import { EXPLAIN_MAX_HITS, explainInstalled, mayMatch, urlFilterLiteral, type ExplainDeps } from '../../src/ui/dashboard/lab-explain.ts';

const req = (url: string, type = 'script', initiator: string | null = 'news.example.ch'): DryRequest => ({ url, type, initiator, source: 'pasted' });

test('urlFilterLiteral picks the longest literal run', () => {
  assert.equal(urlFilterLiteral('||ads.example.net^'), 'ads.example.net');
  assert.equal(urlFilterLiteral('|https://x.example/*/Banner^'), 'https://x.example/');
  assert.equal(urlFilterLiteral('/banner/*/img^'), '/banner/');
  assert.equal(urlFilterLiteral('*'), '');
});

test('mayMatch rejects by type, domains and literal, and never wrongly', () => {
  const p = prepareRequest({ url: 'https://cdn.ads.example.net/A.js', type: 'script', initiator: 'news.example.ch' })!;
  const spec = p.spec.toLowerCase();
  assert.equal(mayMatch({ resourceTypes: ['image'] }, p, spec), false);
  assert.equal(mayMatch({ requestDomains: ['other.example'] }, p, spec), false);
  assert.equal(mayMatch({ requestDomains: ['ads.example.net'] }, p, spec), true);
  assert.equal(mayMatch({ initiatorDomains: ['blog.example'] }, p, spec), false);
  assert.equal(mayMatch({ urlFilter: '||ads.example.net/a.js', isUrlFilterCaseSensitive: true }, p, spec), true, 'case-insensitive pre-check');
  assert.equal(mayMatch({ urlFilter: '/tracker.' }, p, spec), false);
  const doc = prepareRequest({ url: 'https://news.example.ch/', type: 'main_frame' })!;
  assert.equal(mayMatch({ urlFilter: 'news' }, doc, doc.spec), false, 'main_frame needs an explicit type');
  assert.equal(mayMatch({ urlFilter: 'news', resourceTypes: ['main_frame'] }, doc, doc.spec), true);
});

function deps(over: Partial<ExplainDeps> = {}): ExplainDeps & { fetched: string[] } {
  const files: Record<string, unknown> = {
    'rulesets/net/easylist.json': [
      { id: 1, priority: PRIORITY.BLOCK_PROTECTED, action: { type: 'block' }, condition: { urlFilter: '||ads.example.net^', resourceTypes: ['script', 'image'] } },
      { id: 2, priority: PRIORITY.ALLOW, action: { type: 'allow' }, condition: { urlFilter: '||ads.example.net/ok.js' } },
      { id: 3, priority: PRIORITY.BLOCK_PROTECTED, action: { type: 'block' }, condition: { urlFilter: '/never-here/' } },
    ],
    'rulesets/filters/easylist.json': [null, ['||ads.example.net^$script,image'], ['@@||ads.example.net/ok.js']],
    'rulesets/net/privacy.json': [
      { id: 7, priority: PRIORITY.IMPORTANT, action: { type: 'block' }, condition: { urlFilter: '||ads.example.net/ok.js', resourceTypes: ['script'] } },
    ],
    'rulesets/filters/privacy.json': [null, null, null, null, null, null, null, ['||ads.example.net/ok.js$script,important']],
    'rulesets/net/off.json': [{ id: 1, priority: 99, action: { type: 'block' }, condition: {} }],
  };
  const fetched: string[] = [];
  return {
    fetched,
    meta: null,
    enabledRulesets: async () => ['privacy', 'easylist'],
    rulesetPath: (id) => `rulesets/net/${id}.json`,
    fetchJson: async <T>(p: string) => {
      fetched.push(p);
      return (files[p] ?? null) as T | null;
    },
    dynamicRules: async () => [
      { id: RULE_ID.CUSTOM_START, priority: 21, action: { type: 'block' }, condition: { urlFilter: 'ads' } }, // compiled here instead
      { id: RULE_ID.SITES_DISABLED, priority: PRIORITY.SITE_DISABLED, action: { type: 'allowAllRequests' }, condition: { requestDomains: ['off.example'], resourceTypes: ['main_frame'] } },
    ],
    sessionRules: async () => [],
    customText: async () => '! mine\n@@||ads.example.net/ok.js$important\n||unrelated.example^',
    adminLines: () => [],
    ...over,
  };
}

test('every matching rule is listed with its filter text, the winner follows the bands', async () => {
  const d = deps();
  const progress: string[] = [];
  const r = (await explainInstalled([req('https://ads.example.net/ok.js'), req('https://ads.example.net/a.png', 'image'), req('https://clean.example/x.js')], { ...d, progress: (_a, _b, s) => progress.push(s) }))!;
  assert.equal(r.length, 3);
  // ok.js: list block (10), list allow (30), $important block (40) and the user's important allow (50).
  const ok = r[0];
  assert.deepEqual(ok.hits.map((h) => [h.source, h.priority, h.action]), [
    ['custom', PRIORITY.IMPORTANT_ALLOW, 'allow'],
    ['privacy', PRIORITY.IMPORTANT, 'block'],
    ['easylist', PRIORITY.ALLOW, 'allow'],
    ['easylist', PRIORITY.BLOCK_PROTECTED, 'block'],
  ]);
  assert.equal(ok.outcome, 'allow');
  assert.deepEqual(ok.winner, {
    source: 'custom',
    ruleId: 2,
    priority: PRIORITY.IMPORTANT_ALLOW,
    action: 'allow',
    kind: 'allow',
    page: false,
    filters: ['@@||ads.example.net/ok.js$important'],
    filterCount: 1,
    matchedDomain: null,
  });
  // Without the user's exception, the $important list block decides.
  assert.equal(ok.counterfactual?.outcome, 'block');
  assert.equal(ok.counterfactual?.winner?.source, 'privacy');
  assert.equal(r[1].counterfactual, null, 'no counterfactual when a block decides');
  assert.deepEqual(ok.hits[1].filters, ['||ads.example.net/ok.js$script,important']);
  assert.equal(r[1].outcome, 'block');
  assert.deepEqual(r[1].winner?.filters, ['||ads.example.net^$script,image']);
  assert.equal(r[2].outcome, 'none');
  assert.deepEqual(r[2].hits, []);
  assert.deepEqual(progress, ['custom', 'easylist', 'privacy', '']);
  // Only enabled rulesets are read, and a map only where something matched.
  assert.ok(!d.fetched.includes('rulesets/net/off.json'));
});

test('a page-level allowAllRequests (site off) lifts blocks on that page', async () => {
  const r = (await explainInstalled([req('https://ads.example.net/a.js', 'script', 'off.example')], deps()))!;
  assert.equal(r[0].outcome, 'allow');
  assert.equal(r[0].winner?.page, true);
  assert.equal(r[0].winner?.source, '_dynamic');
});

test('bounded: hits are capped, the winner kept; invalid URLs skipped; cancel stops', async () => {
  const many: MatchRule[] = Array.from({ length: EXPLAIN_MAX_HITS + 30 }, (_, i) => ({ id: i + 1, priority: 10, action: { type: 'block' }, condition: { urlFilter: 'x.example' } }));
  many.push({ id: 999, priority: 1, action: { type: 'block' }, condition: { urlFilter: 'x.example' } });
  const d = deps({
    enabledRulesets: async () => ['big'],
    fetchJson: async <T>(p: string) => (p.endsWith('big.json') && p.includes('/net/') ? many : null) as T | null,
    customText: async () => '',
  });
  const r = (await explainInstalled([req('https://x.example/a.js'), req('not a url')], d))!;
  assert.equal(r.length, 1);
  assert.equal(r[0].hits.length, EXPLAIN_MAX_HITS);
  assert.equal(r[0].capped, true);
  assert.equal(r[0].winner?.ruleId, 1);
  let calls = 0;
  const cancelled = await explainInstalled([req('https://x.example/a.js')], { ...d, cancelled: () => ++calls > 0 });
  assert.equal(cancelled, null);
});

test('Lab, settings and context-menu locale keys exist in every language (de-CH spelling)', async () => {
  const { readFileSync } = await import('node:fs');
  const read = (p: string) => readFileSync(new URL(p, import.meta.url), 'utf8');
  const load = (lang: string) => JSON.parse(read(`../../src/_locales/${lang}/messages.json`)) as Record<string, { message: string; placeholders?: object }>;
  const src = ['../../src/ui/dashboard/views/lab.ts', '../../src/ui/dashboard/views/settings.ts', '../../src/background/nerd-menus.ts'].map(read).join('\n');
  const keys = new Set(Array.from(src.matchAll(/'(nerd(?:Lab|Menu|Settings)[A-Za-z]*)'/g), (m) => m[1]!));
  assert.ok(keys.size > 40);
  const de = load('de');
  for (const lang of ['en', 'de', 'fr', 'it']) {
    const m = load(lang);
    for (const k of keys) {
      assert.ok(m[k]?.message, `${lang}: missing ${k}`);
      assert.deepEqual(Object.keys(m[k]!.placeholders ?? {}), Object.keys(de[k]!.placeholders ?? {}), `${lang}: ${k} placeholders`);
    }
  }
  for (const k of keys) assert.ok(!de[k]!.message.includes('ß'), `${k}: no sharp s in de-CH`);
});


test('actionKind names what a rule does', async () => {
  const { actionKind } = await import('../../src/ui/dashboard/lab-explain.ts');
  const k = (priority: number, action: Record<string, unknown>) => actionKind({ priority, action: action as { type: string } });
  assert.equal(k(10, { type: 'block' }), 'block');
  assert.equal(k(30, { type: 'allow' }), 'allow');
  assert.equal(k(1000, { type: 'allowAllRequests' }), 'page');
  assert.equal(k(PRIORITY.STRICT_BLOCK, { type: 'redirect', redirect: { extensionPath: '/pages/blocked.html?list=easylist' } }), 'strict');
  assert.equal(k(50, { type: 'redirect', redirect: { extensionPath: '/pages/blocked.html?list=x' } }), 'strict', 'by target, whatever the priority');
  assert.equal(k(PRIORITY.REDIRECT_ALWAYS, { type: 'redirect', redirect: { extensionPath: '/war/noop.js' } }), 'surrogate');
  assert.equal(k(1, { type: 'redirect', redirect: { transform: { queryTransform: { removeParams: ['utm_source'] } } } }), 'params');
  assert.equal(k(1, { type: 'redirect', redirect: { transform: { query: '' } } }), 'params');
  assert.equal(k(PRIORITY.DEBOUNCE, { type: 'redirect', redirect: { regexSubstitution: 'chrome-extension://x/pages/bounce.html#\\1' } }), 'debounce');
  assert.equal(k(5, { type: 'redirect', redirect: { url: 'https://example.org/' } }), 'redirect');
  assert.equal(k(PRIORITY.GPC_HEADER, { type: 'modifyHeaders', requestHeaders: [{ header: 'Sec-GPC', operation: 'set', value: '1' }] }), 'gpc');
  assert.equal(k(1, { type: 'modifyHeaders', responseHeaders: [{ header: 'csp' }] }), 'headers');
  assert.equal(k(1, { type: 'upgradeScheme' }), 'upgrade');
});

test('counterfactual: without the deciding exception, the next rule decides in Chromium order', async () => {
  const { counterfactual, allowReason } = await import('../../src/ui/dashboard/lab-explain.ts');
  type Hit = import('../../src/ui/dashboard/lab-explain.ts').ExplainHit;
  const hit = (source: string, ruleId: number, priority: number, action: string, kind: Hit['kind']): Hit => ({ source, ruleId, priority, action, kind, page: false, filters: [], filterCount: 0, matchedDomain: null });
  // The 20min.ch case: protection off decides; EasyList and Peter Lowe strict-block the navigation.
  const off = hit('_dynamic', RULE_ID.SITES_DISABLED, PRIORITY.SITE_DISABLED, 'allowAllRequests', 'page');
  const offNoTab = hit('_session', RULE_ID.SESSION_SITES_DISABLED_NO_TAB, PRIORITY.SITE_DISABLED, 'allowAllRequests', 'page');
  const easy = hit('easylist', 1265, PRIORITY.STRICT_BLOCK, 'redirect', 'strict');
  const lowe = hit('peter-lowe', 2, PRIORITY.STRICT_BLOCK, 'redirect', 'strict');
  const gpc = hit('_dynamic', RULE_ID.GPC_HEADER, PRIORITY.GPC_HEADER, 'modifyHeaders', 'gpc');
  assert.equal(allowReason(off), 'siteOff');
  assert.equal(allowReason(offNoTab), 'siteOff');
  const cf = counterfactual([off, offNoTab, easy, lowe, gpc], off)!;
  assert.equal(cf.outcome, 'redirect');
  assert.equal(cf.winner, easy, 'equal priority and action: the first listed');
  // A list exception at 30 beats the strict block at 29, a user exception at 50 beats an $important block.
  const listAllow = hit('easylist', 9, PRIORITY.ALLOW, 'allow', 'allow');
  assert.equal(counterfactual([off, listAllow, easy], off)!.winner, listAllow);
  const userAllow = hit('custom', 3, PRIORITY.IMPORTANT_ALLOW, 'allow', 'allow');
  const important = hit('privacy', 7, PRIORITY.IMPORTANT, 'block', 'block');
  const cf2 = counterfactual([userAllow, important, listAllow, easy], userAllow)!;
  assert.equal(cf2.winner, important, 'other filter exceptions are dropped too, the $important block decides');
  // Proceed anyway: the strict block comes back; nothing left: loads normally (GPC only modifies headers).
  const proceed = hit('_session', RULE_ID.SESSION_PROCEED_START + 4, PRIORITY.PROCEED_ANYWAY, 'allow', 'allow');
  assert.equal(allowReason(proceed), 'proceed');
  assert.equal(counterfactual([proceed, easy], proceed)!.winner, easy);
  const bisect = hit('_session', RULE_ID.SESSION_BISECT_START, PRIORITY.BISECT_ALLOW, 'allow', 'allow');
  assert.equal(allowReason(bisect), 'bisect');
  const none = counterfactual([bisect, gpc], bisect)!;
  assert.equal(none.winner, null);
  assert.equal(none.outcome, 'modifyHeaders');
  assert.equal(none.headers, gpc);
  // Only an allow decider has a counterfactual.
  assert.equal(counterfactual([easy, off], easy), null);
  assert.equal(counterfactual([], null), null);
});

test('merged rules: the matched domain, its rebuilt filter text and the filter cell', async () => {
  const { deriveFilter, filterDisplay, longestDomain, mentionsDomain, moreOfRule } = await import('../../src/ui/dashboard/lab-explain.ts');
  assert.equal(longestDomain('pagead2.googlesyndication.com', ['com', 'googlesyndication.com', 'syndication.com']), 'googlesyndication.com');
  assert.equal(longestDomain('evilgooglesyndication.com', ['googlesyndication.com']), null);
  assert.equal(mentionsDomain('||googlesyndication.com^', 'googlesyndication.com'), true);
  assert.equal(mentionsDomain('||adgooglesyndication.com^', 'googlesyndication.com'), false);
  assert.equal(mentionsDomain('127.0.0.1 googlesyndication.com', 'googlesyndication.com'), true);
  assert.equal(moreOfRule([null, ['a', 'b', '+50358 more']], 1), 50358);
  assert.equal(moreOfRule(null, 1), 0);
  const domains = ['000491b06a.com', '0017c6c37c.com', 'googlesyndication.com'];
  assert.equal(deriveFilter(['||000491b06a.com^', '||0017c6c37c.com^'], domains, 'googlesyndication.com'), '||googlesyndication.com^');
  assert.equal(deriveFilter(['127.0.0.1 000491b06a.com'], domains, 'googlesyndication.com'), '127.0.0.1 googlesyndication.com');
  assert.equal(deriveFilter(['/regex/'], domains, 'googlesyndication.com'), null);

  const url = 'https://pagead2.googlesyndication.com/pcs/click?xai=x&adurl=https://www.20min.ch/';
  // The text of the request's domain was not recorded: the rebuilt one comes first, highlighted.
  const merged = { filters: ['||000491b06a.com^', '||0017c6c37c.com^', '||0019x.com^'], filterCount: 50378, matchedDomain: 'googlesyndication.com', derived: '||googlesyndication.com^' };
  assert.deepEqual(filterDisplay(merged, url), { shown: ['||googlesyndication.com^'], relevant: 1, derived: true, more: 50377 });
  // A recorded text that names the host or a parent domain wins over the rebuilt one.
  const recorded = { filters: ['||a.example^', '||googlesyndication.com^$script', '||pagead2.googlesyndication.com^'], filterCount: 40, matchedDomain: 'googlesyndication.com' };
  assert.deepEqual(filterDisplay(recorded, url), { shown: ['||pagead2.googlesyndication.com^', '||googlesyndication.com^$script'], relevant: 2, derived: false, more: 38 });
  // Nothing identifiable: the first recorded texts, as before, with the full count.
  assert.deepEqual(filterDisplay({ filters: ['a', '', 'b', 'c', 'd'], filterCount: 0, matchedDomain: null }, 'not a url'), { shown: ['a', 'b', 'c'], relevant: 0, derived: false, more: 1 });
  // A single filter is never "highlighted".
  assert.deepEqual(filterDisplay({ filters: ['||googlesyndication.com^'], filterCount: 1, matchedDomain: null }, url), { shown: ['||googlesyndication.com^'], relevant: 0, derived: false, more: 0 });
});

test('explain run: a merged strict-block rule shows the request domain, protection off has a counterfactual', async () => {
  const domains = ['000491b06a.com', '0017c6c37c.com', 'googlesyndication.com', 'zz.example'];
  const d = deps({
    enabledRulesets: async () => ['easylist'],
    fetchJson: async <T>(p: string) =>
      (p === 'rulesets/net/easylist.json'
        ? [{ id: 1265, priority: PRIORITY.STRICT_BLOCK, action: { type: 'redirect', redirect: { extensionPath: '/pages/blocked.html?list=easylist' } }, condition: { requestDomains: domains, resourceTypes: ['main_frame'] } }]
        : p === 'rulesets/filters/easylist.json'
          ? Object.assign([], { 1265: ['||000491b06a.com^', '||0017c6c37c.com^', '+2 more'] })
          : null) as T | null,
    dynamicRules: async () => [
      { id: RULE_ID.SITES_DISABLED, priority: PRIORITY.SITE_DISABLED, action: { type: 'allowAllRequests' }, condition: { requestDomains: ['20min.ch'], resourceTypes: ['main_frame'] } },
    ],
    customText: async () => '',
  });
  const [r] = (await explainInstalled([{ url: 'https://pagead2.googlesyndication.com/pcs/click?xai=x&adurl=https://www.20min.ch/', type: 'main_frame', initiator: 'www.20min.ch', source: 'pasted' }], d))!;
  assert.equal(r!.winner?.action, 'allowAllRequests');
  assert.equal(r!.winner?.page, true);
  const strict = r!.hits.find((h) => h.source === 'easylist')!;
  assert.equal(strict.kind, 'strict');
  assert.equal(strict.matchedDomain, 'googlesyndication.com');
  assert.equal(strict.derived, '||googlesyndication.com^');
  assert.equal(strict.filterCount, 4);
  assert.equal(r!.counterfactual?.winner?.source, 'easylist');
  assert.equal(r!.counterfactual?.outcome, 'redirect');
});

test('setRequestType rewrites one pasted line; parseUrlList keeps lines and marks guessed types', async () => {
  const { parseUrlList, setRequestType } = await import('../../src/ui/dashboard/lab-core.ts');
  const text = '! note\nhttps://a.example/click?x=1 www.news.ch\nhttps://b.example/a.js script';
  const { requests } = parseUrlList(text);
  assert.deepEqual(requests.map((r) => [r.line, r.type, r.typeGuessed ?? false]), [
    [1, 'other', true],
    [2, 'script', false],
  ]);
  const next = setRequestType(text, 1, requests[0]!, 'main_frame');
  assert.equal(next, '! note\nhttps://a.example/click?x=1 main_frame www.news.ch\nhttps://b.example/a.js script');
  assert.deepEqual(parseUrlList(next).requests.map((r) => r.type), ['main_frame', 'script']);
  assert.equal(setRequestType(text, 9, requests[0]!, 'image'), text);
});
