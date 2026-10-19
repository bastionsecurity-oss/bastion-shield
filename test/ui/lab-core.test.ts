// Tests for the nerd-mode Lab logic (src/ui/dashboard/lab-core.ts): the filter
// playground (per-line compile with the custom-filter compiler, dry run with
// the DNR matcher), pasted request lists, integrity helpers, provenance and
// blame lookups.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { ActivityEvent, BuildMeta } from '../../src/shared/types.ts';
import {
  blameFor,
  compilePlayground,
  dryRun,
  filtersOfRule,
  groupHits,
  guessType,
  integrityRows,
  integritySummary,
  isIntegrityManifest,
  packagedCandidates,
  parseRuleRef,
  parseUrlList,
  provenance,
  requestsFromEvents,
  settleRow,
  toHex,
  type DryRequest,
} from '../../src/ui/dashboard/lab-core.ts';

const meta = {
  builtAt: '2026-10-18T10:00:00.000Z',
  extensionVersion: '0.1.0.2910',
  vendor: { ublock: 'abc', braveResources: 'def', braveLists: 'ghi' },
  rulesetToList: { ublock: 'ublock', 'ublock.regex': 'ublock', easylist: 'easylist' },
  redirectResources: { 'noop.js': '/war/noop.js' },
  lists: [
    { id: 'ublock', sources: [{ url: 'https://ublockorigin.github.io/uAssets/filters/filters.txt', sha256: 'a'.repeat(64), bytes: 10 }] },
    { id: 'easylist', sources: [{ url: 'https://easylist.to/easylist/easylist.txt', sha256: 'b'.repeat(64), bytes: 20, version: '202610181000' }] },
    { id: 'bastion', sources: [{ url: 'https://bastion.example/list.txt', sha256: 'c'.repeat(64), bytes: 30 }] },
  ],
} as unknown as BuildMeta;

const req = (url: string, type: string, initiator: string | null = 'news.example.ch', extra: Partial<DryRequest> = {}): DryRequest => ({ url, type, initiator, source: 'pasted', ...extra });

test('compilePlayground: kinds, line numbers, comments skipped', () => {
  const text = [
    '! comment',
    '||ads.example^',
    '',
    'example.com##.banner',
    'example.com##+js(set-constant, x, 1)',
    '/ads.$popup',
    '||x.example/a.js$script,redirect=noop.js',
    '||y.example^$badfilter',
    '||y.example^',
  ].join('\n');
  const { filters, truncated } = compilePlayground(text, meta);
  assert.equal(truncated, false);
  const kinds = filters.map((f) => [f.line, f.kind]);
  assert.deepEqual(kinds, [
    [2, 'network'],
    [4, 'cosmetic'],
    [5, 'scriptlet'],
    [6, 'error'],
    [7, 'network'],
    [8, 'inert'],
    [9, 'inert'],
  ]);
  assert.deepEqual(filters[3].errors, ['unsupported-type:popup']);
  assert.equal(filters[4].rules[0].action.type, 'redirect');
  assert.ok(filters.every((f, i) => f.index === i));
});

test('compilePlayground: an unknown redirect resource is an error, !#if blocks are resolved', () => {
  const { filters } = compilePlayground('||x.example^$script,redirect=nope.js\n!#if false\n||hidden.example^\n!#endif', meta);
  assert.equal(filters.length, 1);
  assert.equal(filters[0].kind, 'error');
});

test('dryRun: matches, winner across filters, types and already-handled counts', () => {
  const { filters } = compilePlayground('||ads.example^\n@@||ads.example/ok.js$script\n||cdn.example^$image\nexample.com##.x', meta);
  const requests: DryRequest[] = [
    req('https://ads.example/a.js', 'script'),
    req('https://ads.example/ok.js', 'script'),
    req('https://ads.example/p.gif', 'image', 'news.example.ch', { source: 'history', kind: 'blocked', list: 'easylist' }),
    req('https://cdn.example/p.gif', 'image'),
    req('https://cdn.example/p.js', 'script'),
    req('not a url', 'script'),
  ];
  const r = dryRun(filters, requests);
  assert.equal(r.requests, 5);
  assert.equal(r.unparsable, 1);
  assert.equal(r.matched, 4);
  const [block, allow, cdn, cosmetic] = r.perFilter;
  assert.equal(block.matches, 3);
  assert.equal(block.decided, 2, 'the @@ exception decides ok.js');
  assert.deepEqual(block.types, { script: 2, image: 1 });
  assert.equal(block.alreadyHandled, 1);
  assert.deepEqual(block.actions, ['block']);
  assert.equal(allow.matches, 1);
  assert.equal(allow.decided, 1);
  assert.equal(allow.hits[0].outcome, 'allow');
  assert.equal(cdn.matches, 1);
  assert.equal(cosmetic.matches, 0);
  assert.deepEqual(r.outcomes, { block: 3, allow: 1 });
});

test('dryRun: $domain and party conditions use the request initiator', () => {
  const { filters } = compilePlayground('||t.example^$domain=news.example.ch\n||u.example^$3p', meta);
  const r = dryRun(filters, [
    req('https://t.example/x.js', 'script', 'news.example.ch'),
    req('https://t.example/x.js', 'script', 'shop.example.ch'),
    req('https://t.example/x.js', 'script', null),
    req('https://u.example/x.js', 'script', 'www.u.example'),
    req('https://u.example/x.js', 'script', null),
  ]);
  assert.equal(r.perFilter[0].matches, 1);
  assert.equal(r.perFilter[1].matches, 1, 'no initiator counts as third party, same site does not');
});

test('groupHits groups repeated requests, most frequent first', () => {
  const { filters } = compilePlayground('||ads.example^', meta);
  const r = dryRun(filters, [req('https://ads.example/b.js', 'script'), req('https://ads.example/a.js', 'script'), req('https://ads.example/a.js', 'script')]);
  const g = groupHits(r.perFilter[0].hits);
  assert.deepEqual(g.map((x) => [x.url, x.count]), [
    ['https://ads.example/a.js', 2],
    ['https://ads.example/b.js', 1],
  ]);
});

test('requestsFromEvents and parseUrlList', () => {
  const ev = { t: 1, tabId: -1, frameId: 0, kind: 'blocked', url: 'https://a.example/x', host: 'a.example', type: 'script', site: 'news.ch', thirdParty: true, list: 'easylist' } as ActivityEvent;
  assert.deepEqual(requestsFromEvents([ev]), [{ url: 'https://a.example/x', type: 'script', initiator: 'news.ch', tabless: true, source: 'history', kind: 'blocked', list: 'easylist' }]);
  const { requests, invalid } = parseUrlList('https://a.example/x.js\n! note\nb.example/p.png image https://news.ch/page\nhttps://c.example/ xhr news.ch\nhttp://[bad\n\nhttps://d.example/f doc');
  assert.deepEqual(invalid, [5]);
  assert.deepEqual(
    requests.map((r) => [r.url, r.type, r.initiator]),
    [
      ['https://a.example/x.js', 'script', null],
      ['https://b.example/p.png', 'image', 'news.ch'],
      ['https://c.example/', 'xmlhttprequest', 'news.ch'],
      ['https://d.example/f', 'main_frame', null],
    ],
  );
  assert.equal(guessType('https://x.example/a.woff2?v=1'), 'font');
  assert.equal(guessType('https://x.example/'), 'other');
});

test('integrity helpers', () => {
  const m = { algorithm: 'sha256', builtAt: 'x', files: { 'rulesets/net/b.json': 'f'.repeat(64), 'rulesets/a.json': '0'.repeat(64) } };
  assert.equal(isIntegrityManifest(m), true);
  assert.equal(isIntegrityManifest({ ...m, algorithm: 'md5' }), false);
  assert.equal(isIntegrityManifest({ ...m, files: { a: 'XYZ' } }), false);
  const rows = integrityRows(m as never);
  assert.deepEqual(rows.map((r) => r.path), ['rulesets/a.json', 'rulesets/net/b.json']);
  const settled = [settleRow(rows[0], '0'.repeat(64)), settleRow(rows[1], 'e'.repeat(64))];
  assert.deepEqual(settled.map((r) => r.status), ['ok', 'mismatch']);
  assert.equal(settleRow(rows[0], null).status, 'missing');
  assert.deepEqual(integritySummary(settled), { pending: 0, ok: 1, mismatch: 1, missing: 0 });
  assert.equal(toHex(new Uint8Array([0, 15, 255]).buffer), '000fff');
  assert.deepEqual(packagedCandidates('rulesets/net/easylist.json'), ['rulesets/net/easylist.json', 'easylist.json']);
  assert.deepEqual(packagedCandidates('rulesets/filters/easylist.json'), ['rulesets/filters/easylist.json']);
});

test('provenance, rule references, transparency maps and blame', () => {
  const p = provenance(meta);
  assert.equal(p.builtAt, meta.builtAt);
  assert.equal(p.lists[1].sources[0].version, '202610181000');
  assert.deepEqual(parseRuleRef('ublock.regex:12'), { rulesetId: 'ublock.regex', ruleId: 12 });
  assert.equal(parseRuleRef('_dynamic:0'), null);
  assert.equal(parseRuleRef('no-id'), null);
  assert.equal(parseRuleRef('../x:1'), null);
  assert.deepEqual(filtersOfRule([null, ['||a^', '||b^', '+3 more']], 1), ['||a^', '||b^']);
  assert.deepEqual(filtersOfRule(null, 1), []);
  const one = blameFor(meta, 'ublock', '||ads.example^');
  assert.equal(one.length, 1);
  assert.equal(one[0].links[0].kind, 'blame');
  const all = blameFor(meta, 'all', '||ads.example^');
  assert.deepEqual(all.map((g) => g.listId), ['ublock', 'easylist'], 'lists without GitHub sources are left out');
  assert.equal(all[1].links[0].kind, 'search');
});

test('parseLabHash: sections, url / site / type, filter, bounds', async () => {
  const { parseLabHash, linkRequestLine, LINK_MAX } = await import('../../src/ui/dashboard/lab-core.ts');
  assert.deepEqual(parseLabHash('#lab'), { section: 'playground' });
  assert.deepEqual(parseLabHash('#lab/integrity'), { section: 'integrity' });
  assert.deepEqual(parseLabHash('#lab/nope?filter=x'), { section: 'playground', filter: 'x' });
  const u = 'https://ads.example.net/a.js?x=1&y=2';
  const link = parseLabHash(`#lab?url=${encodeURIComponent(u)}&site=News.Example.CH&type=script`);
  assert.deepEqual(link, { section: 'playground', url: u, site: 'news.example.ch', type: 'script' });
  assert.equal(linkRequestLine(link), `${u} script news.example.ch`);
  assert.deepEqual(parseLabHash('#lab?url=javascript%3Aalert(1)&site=%3Cb%3E&type=bogus'), { section: 'playground' });
  assert.deepEqual(parseLabHash(`#lab/blame?filter=${encodeURIComponent('||doubleclick.net^$third-party')}`), { section: 'blame', filter: '||doubleclick.net^$third-party' });
  assert.equal(parseLabHash(`#lab?filter=${'a'.repeat(LINK_MAX + 10)}`).filter?.length, LINK_MAX);
  // parseUrlList reads the line back with the same type and page.
  const back = parseUrlList(linkRequestLine(link)).requests[0];
  assert.deepEqual([back.url, back.type, back.initiator], [u, 'script', 'news.example.ch']);
});
