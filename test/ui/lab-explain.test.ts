// Tests for the Lab's explain mode (src/ui/dashboard/lab-explain.ts): the
// cheap pre-checks, page-level allowAllRequests, the winner across sources
// and the streaming runner with fake rulesets, custom and dynamic rules.
//
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
  assert.deepEqual(ok.winner, { source: 'custom', ruleId: 2, priority: PRIORITY.IMPORTANT_ALLOW, action: 'allow', page: false, filters: ['@@||ads.example.net/ok.js$important'] });
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

test('relevantFilters puts the filters naming the host first and caps the rest', async () => {
  const { relevantFilters } = await import('../../src/ui/dashboard/lab-explain.ts');
  const fs = ['||awfonts.com^$script', '||bbthat.com^', '||google-analytics.com^$script', '||www.google-analytics.com/x', '||zz.example^'];
  assert.deepEqual(relevantFilters(fs, 'https://www.google-analytics.com/analytics.js'), { shown: ['||www.google-analytics.com/x', '||google-analytics.com^$script', '||awfonts.com^$script'], more: 2 });
  assert.deepEqual(relevantFilters(['a', '', 'b'], 'not a url', 5), { shown: ['a', 'b'], more: 0 });
});
