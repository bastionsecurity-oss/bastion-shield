// Tests for cosmetic filtering in the service worker: candidate host keys,
// merging shard entries with list masks, exceptions and flags, CSS assembly,
// generic token lookup and the service's insertCSS flow (src/background/cosmetic.ts).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shardName, shardOf } from '../../src/shared/hash.ts';
import type { CosmeticHostEntry, CosmeticMeta, CosmeticShard, GenericIndex } from '../../src/shared/types.ts';
import {
  buildHideCss,
  buildHostCss,
  CosmeticService,
  customHighlyGeneric,
  genericHighCopies,
  genericHighExcludedSet,
  genericLookupFromText,
  genericSelectorsForTokens,
  hostKeyCandidates,
  resolveHostCosmetic,
} from '../../src/background/cosmetic.ts';
import type { CosmeticConfig, CosmeticTarget, CustomCosmetic } from '../../src/background/cosmetic.ts';

const A = 1 << 0; // list A
const B = 1 << 1; // list B
const C = 1 << 2; // disabled list

test('candidate host keys: hostname, parents, entities', () => {
  assert.deepEqual(hostKeyCandidates('www.google.co.uk'), [
    'www.google.co.uk',
    'google.co.uk',
    'co.uk',
    'www.google.co.*',
    'www.google.*',
    'google.co.*',
    'google.*',
    'co.*',
  ]);
  assert.deepEqual(hostKeyCandidates('localhost'), ['localhost']);
  assert.deepEqual(hostKeyCandidates('10.0.0.1'), ['10.0.0.1']);
  assert.deepEqual(hostKeyCandidates(''), []);
});

test('entries are filtered by the enabled mask', () => {
  const entries: CosmeticHostEntry[] = [
    [0, '.ad', A],
    [0, '.promo', C],
    [0, '.both', A | C],
  ];
  const r = resolveHostCosmetic([entries], A | B, ['example.com']);
  assert.deepEqual(r.hide.sort(), ['.ad', '.both']);
  assert.equal(r.genericAllowed, true);
});

test('exceptions remove hide and style entries; procedural exceptions remove procedural', () => {
  const proc = JSON.stringify({ raw: 'example.com##div:has-text(Werbung)', selector: 'div', tasks: [['has-text', 'Werbung']] });
  const other = JSON.stringify({ raw: 'example.com##p:has-text(Anzeige)', selector: 'p', tasks: [['has-text', 'Anzeige']] });
  const host: CosmeticHostEntry[] = [
    [0, '.ad', A],
    [0, '.keep', A],
    [3, '.x { color: red }', A],
    [2, proc, A],
    [2, other, B],
  ];
  const parent: CosmeticHostEntry[] = [
    [1, '.ad', B],
    [1, '.x { color: red }', A],
    [5, 'div:has-text(Werbung)', A],
  ];
  const r = resolveHostCosmetic([host, parent], A | B, ['www.example.com', 'example.com']);
  assert.deepEqual(r.hide, ['.keep']);
  assert.deepEqual(r.styles, []);
  assert.deepEqual(r.procedural, [other]);
  assert.ok(r.exceptions.has('.ad'));
});

test('flags: specifichide drops specific filters, generichide/elemhide disable generic', () => {
  const entries: CosmeticHostEntry[] = [
    [0, '.ad', A],
    [3, '.y{}', A],
    [4, 'specifichide', A],
  ];
  const s = resolveHostCosmetic([entries], A, ['a.ch']);
  assert.deepEqual(s.hide, []);
  assert.deepEqual(s.styles, []);
  assert.equal(s.genericAllowed, true);
  const g = resolveHostCosmetic([[[0, '.ad', A], [4, 'generichide', A]]], A, ['a.ch']);
  assert.deepEqual(g.hide, ['.ad']);
  assert.equal(g.genericAllowed, false);
  const e = resolveHostCosmetic([[[0, '.ad', A], [4, 'elemhide', A]]], A, ['a.ch']);
  assert.deepEqual(e.hide, []);
  assert.equal(e.genericAllowed, false);
  // A flag from a disabled list has no effect.
  const off = resolveHostCosmetic([[[0, '.ad', A], [4, 'elemhide', C]]], A, ['a.ch']);
  assert.deepEqual(off.hide, ['.ad']);
});

test('custom filters match hosts and entities, honouring ~exclusions', () => {
  const custom: CustomCosmetic = {
    specific: [
      { kind: 0, hosts: ['google.*'], excludedHosts: [], payload: '#tads', raw: 'google.*###tads' },
      { kind: 0, hosts: ['example.com'], excludedHosts: ['shop.example.com'], payload: '.banner', raw: '' },
      { kind: 1, hosts: ['example.com'], excludedHosts: [], payload: '.list-exc', raw: '' },
    ],
    generic: [
      { selector: '.gen', token: '.gen', excludedHosts: [], raw: '' },
      { selector: 'div[data-ad]', token: null, excludedHosts: ['example.com'], raw: '' },
      { selector: 'aside[id^="ad-"]', token: null, excludedHosts: [], raw: '' },
    ],
  };
  const g = resolveHostCosmetic([], A, hostKeyCandidates('www.google.ch'), custom);
  assert.deepEqual(g.hide, ['#tads']);
  const shop = resolveHostCosmetic([[[0, '.list-exc', A]]], A, hostKeyCandidates('shop.example.com'), custom);
  assert.deepEqual(shop.hide, []);
  const cands = hostKeyCandidates('www.example.com');
  const www = resolveHostCosmetic([], A, cands, custom);
  assert.deepEqual(www.hide, ['.banner']);
  assert.deepEqual(customHighlyGeneric(custom, www, cands), ['aside[id^="ad-"]']);
});

test('CSS is grouped in blocks of 1,000 selectors and closed with display:none', () => {
  const sels = Array.from({ length: 2500 }, (_, i) => `.s${i}`);
  const css = buildHideCss(sels);
  const blocks = css.split('{display:none!important}').filter((b) => b.trim() !== '');
  assert.equal(blocks.length, 3);
  assert.equal(blocks[0].split(',\n').length, 1000);
  assert.equal(blocks[2].split(',\n').length, 500);
  assert.ok(css.startsWith('.s0,\n.s1'));
  assert.equal(buildHideCss([]), '');
  const host = resolveHostCosmetic([[[0, '.a', A], [3, '.b { opacity: 0 !important }', A]]], A, ['a.ch']);
  assert.equal(buildHostCss(host, ['.c', '.a']), '.a,\n.c{display:none!important}\n.b { opacity: 0 !important }');
});

test('generic token lookup filters by mask, exceptions and custom exclusions', () => {
  const index: GenericIndex = {
    tokens: {
      '.ad-banner': [
        ['.ad-banner', A],
        ['div.ad-banner > img', C],
      ],
      '#sponsor': [['#sponsor', B]],
      '.ok': [['.ok', A]],
    },
  };
  const host = { exceptions: new Set(['.ok']) };
  const custom: CustomCosmetic = { specific: [], generic: [{ selector: '.mine', token: '.mine', excludedHosts: ['x.ch'], raw: '' }] };
  const out = genericSelectorsForTokens(index, ['.ad-banner', '#sponsor', '.ok', '.mine', '.unknown', '__proto__'], A | B, host, ['a.ch'], custom);
  assert.deepEqual(out.sort(), ['#sponsor', '.ad-banner', '.mine']);
  const excluded = genericSelectorsForTokens(index, ['.mine'], A, host, ['sub.x.ch', 'x.ch'], custom);
  assert.deepEqual(excluded, []);
});

test('generic index text is searched in place, one sorted token per line (PERF-5)', () => {
  const tokens: Record<string, [string, number][]> = {
    '#a': [['#a', A]],
    '#b"q': [['#b\\"q', B]],
    '.x\\:y': [['.x\\:y', A]],
    '.ärger': [['.ärger', A]],
    '.ad,\n': [['.ad', A]],
    '.z': [['div.z', A], ['.z', C]],
  };
  // The layout tools/lib/cosmetic.ts writes.
  const lines = Object.keys(tokens)
    .sort()
    .map((t) => `${JSON.stringify(t)}:${JSON.stringify(tokens[t])}`);
  const text = `{"tokens":{\n${lines.join(',\n')}\n}}\n`;
  assert.deepEqual(JSON.parse(text), { tokens }, 'still plain JSON');
  const lookup = genericLookupFromText(text)!;
  for (const [t, v] of Object.entries(tokens)) assert.deepEqual(lookup.get(t), v, t);
  for (const t of ['#', '#c', '.a', '__proto__', 'constructor', '', '.zz']) assert.equal(lookup.get(t), undefined, t);
  assert.deepEqual(lookup.get('#a'), [['#a', A]], 'cached result');
  assert.deepEqual(genericSelectorsForTokens(lookup, ['.z', '#a', '#nope'], A, { exceptions: new Set() }, ['a.ch']).sort(), ['#a', 'div.z']);
  // Empty index, the older single-line layout, garbage.
  assert.equal(genericLookupFromText('{"tokens":{\n\n}}\n')!.get('#a'), undefined);
  assert.deepEqual(genericLookupFromText(JSON.stringify({ tokens }))!.get('.z'), tokens['.z']);
  assert.equal(genericLookupFromText('not json'), null);
});

test('generic-high filtered copy: the selectors of every enabled list on hosts the single registration skips', () => {
  const meta: CosmeticMeta = {
    shards: 256,
    genericHighCss: { easylist: 'cosmetic/generic-high/easylist.css', ublock: 'cosmetic/generic-high/ublock.css', other: null, off: 'cosmetic/generic-high/off.css' },
    genericHighExcludedHosts: { easylist: ['example.com'], other: ['other.example'], off: ['disabled-list.example'] },
    genericHideHosts: ['hide.example'],
    genericHighSelectorsFile: 'cosmetic/generic-high.json',
  };
  const selectors = { easylist: ['.a', '.b', '.c'], ublock: ['.u'], other: ['.z'], off: ['.o'] };
  const enabled = new Set(['easylist', 'ublock', 'other']);
  const host = { exceptions: new Set(['.b']), genericAllowed: true };
  assert.deepEqual([...genericHighExcludedSet(meta, enabled)].sort(), ['example.com', 'hide.example']);
  // Excluded because of easylist's exception: ublock's CSS is missing there too, so it is copied as well.
  assert.deepEqual(genericHighCopies(meta, selectors, enabled, ['www.example.com', 'example.com'], host), ['.a', '.c', '.u']);
  // A generichide host from a list whose flag does not apply (generic allowed): full copy.
  assert.deepEqual(genericHighCopies(meta, selectors, enabled, ['hide.example'], host), ['.a', '.c', '.u']);
  assert.deepEqual(genericHighCopies(meta, selectors, enabled, ['news.ch'], host), []);
  // Exclusions of a disabled list do not count.
  assert.deepEqual(genericHighCopies(meta, selectors, enabled, ['disabled-list.example'], host), []);
  assert.deepEqual(genericHighCopies(meta, selectors, enabled, ['example.com'], { ...host, genericAllowed: false }), []);
  assert.deepEqual(genericHighCopies(meta, selectors, new Set(), ['example.com'], host), []);
});

// --- service ---------------------------------------------------------------

function makeService(shards: Record<string, CosmeticShard>, opts: { off?: string[]; generic?: GenericIndex; meta?: CosmeticMeta; high?: Record<string, string[]> } = {}) {
  const inserted: { target: CosmeticTarget; css: string }[] = [];
  const loads: string[] = [];
  const meta: CosmeticMeta = opts.meta ?? { shards: 256, genericHighCss: {}, genericHighExcludedHosts: {}, genericHighSelectorsFile: 'cosmetic/generic-high.json' };
  const cfg: CosmeticConfig = {
    enabledMask: A | B,
    enabledListIds: new Set(['a', 'b']),
    deAmp: true,
    custom: { specific: [], generic: [] },
    isOff: (h) => (opts.off ?? []).some((o) => h === o || h.endsWith(`.${o}`)),
  };
  const svc = new CosmeticService({
    loadMeta: async () => meta,
    loadShard: async (name) => {
      loads.push(name);
      return shards[name] ?? null;
    },
    loadGeneric: async () => opts.generic ?? { tokens: {} },
    loadGenericHigh: async () => opts.high ?? null,
    config: () => cfg,
    insertCss: async (target, css) => {
      inserted.push({ target, css });
    },
  });
  return { svc, inserted, loads };
}

function shardsFor(entries: Record<string, CosmeticHostEntry[]>): Record<string, CosmeticShard> {
  const out: Record<string, CosmeticShard> = {};
  for (const [key, list] of Object.entries(entries)) {
    const n = shardName(shardOf(key));
    out[n] ??= { hosts: {} };
    out[n].hosts[key] = list;
  }
  return out;
}

test('service: frame lookup inserts CSS with documentId and caches shards', async () => {
  const proc = JSON.stringify({ raw: 'x', selector: 'div', tasks: [] });
  const shards = shardsFor({
    'example.com': [[0, '.ad', A], [2, proc, A]],
    'example.*': [[0, '.entity-ad', B]],
  });
  const { svc, inserted, loads } = makeService(shards, { generic: { tokens: { '.t': [['.t', A]] } } });
  const res = await svc.onFrame({ type: 'cosmetic:frame', url: 'https://www.example.com/page' }, { tabId: 3, frameId: 0, documentId: 'DOC', tabUrl: 'https://www.example.com/page' });
  assert.equal(res.off, false);
  assert.equal(res.deAmp, true);
  assert.equal(res.generic, true);
  assert.deepEqual(res.procedural, [proc]);
  assert.match(res.css, /\.ad/);
  assert.match(res.css, /\.entity-ad/);
  assert.equal(inserted.length, 1);
  assert.deepEqual(inserted[0].target, { tabId: 3, frameId: 0, documentId: 'DOC' });
  const n = loads.length;
  await svc.onFrame({ type: 'cosmetic:frame', url: 'https://www.example.com/other' }, { tabId: 3, frameId: 2, tabUrl: 'https://www.example.com/' });
  assert.equal(loads.length, n, 'host result cached, no new shard loads');
  assert.deepEqual(inserted[1].target, { tabId: 3, frameId: 2 });
});

test('service: protection off for the top page answers off for every frame', async () => {
  const { svc, inserted } = makeService(shardsFor({ 'ads.net': [[0, '.ad', A]] }), { off: ['example.com'] });
  const res = await svc.onFrame({ type: 'cosmetic:frame', url: 'https://ads.net/frame' }, { tabId: 1, frameId: 5, tabUrl: 'https://www.example.com/' });
  assert.deepEqual(res, { off: true, css: '', procedural: [], generic: false, deAmp: false });
  assert.equal(inserted.length, 0);
});

test('service: about:blank frames inherit the origin; tokens produce generic CSS', async () => {
  const { svc, inserted } = makeService(shardsFor({ 'example.com': [[1, '#excepted', A]] }), {
    generic: { tokens: { '#banner': [['#banner', A]], '#excepted': [['#excepted', A]] } },
  });
  const sender = { tabId: 9, frameId: 1, url: 'about:blank', origin: 'https://example.com', tabUrl: 'https://example.com/' };
  const res = await svc.onTokens({ type: 'cosmetic:tokens', url: 'about:blank', tokens: ['#banner', '#excepted', 42 as unknown as string] }, sender);
  assert.equal(res.css, '#banner{display:none!important}');
  assert.equal(inserted.length, 1);
  const none = await svc.onTokens({ type: 'cosmetic:tokens', url: 'https://example.com/', tokens: ['#nothing'] }, sender);
  assert.equal(none.css, '');
  assert.equal(inserted.length, 1);
});

test('service: generichide on the host disables the token surveyor', async () => {
  const { svc } = makeService(shardsFor({ 'example.com': [[4, 'generichide', A]] }), { generic: { tokens: { '#banner': [['#banner', A]] } } });
  const frame = await svc.onFrame({ type: 'cosmetic:frame', url: 'https://example.com/' }, { tabId: 1, frameId: 0, tabUrl: 'https://example.com/' });
  assert.equal(frame.generic, false);
  const res = await svc.onTokens({ type: 'cosmetic:tokens', url: 'https://example.com/', tokens: ['#banner'] }, { tabId: 1, frameId: 0 });
  assert.equal(res.css, '');
});

test('service: hosts skipped by the generic-high registration get the filtered copy of all enabled lists', async () => {
  const meta: CosmeticMeta = {
    shards: 256,
    genericHighCss: { a: 'cosmetic/generic-high/a.css', b: 'cosmetic/generic-high/b.css' },
    genericHighExcludedHosts: { a: ['example.com'], b: [] },
    genericHideHosts: ['nogeneric.ch'],
    genericHighSelectorsFile: 'cosmetic/generic-high.json',
  };
  const high = { a: ['.ha', '.excepted'], b: ['.hb'] };
  const { svc } = makeService(shardsFor({ 'example.com': [[1, '.excepted', A]], 'nogeneric.ch': [[4, 'generichide', A]] }), { meta, high });
  const res = await svc.onFrame({ type: 'cosmetic:frame', url: 'https://www.example.com/' }, { tabId: 1, frameId: 0, tabUrl: 'https://www.example.com/' });
  assert.match(res.css, /.ha/);
  assert.match(res.css, /.hb/, "list b's CSS is skipped there too");
  assert.doesNotMatch(res.css, /.excepted/);
  const hidden = await svc.onFrame({ type: 'cosmetic:frame', url: 'https://nogeneric.ch/' }, { tabId: 1, frameId: 0, tabUrl: 'https://nogeneric.ch/' });
  assert.equal(hidden.css, '', 'generichide: no copy');
  const other = await svc.onFrame({ type: 'cosmetic:frame', url: 'https://news.ch/' }, { tabId: 1, frameId: 0, tabUrl: 'https://news.ch/' });
  assert.equal(other.css, '', 'registered CSS applies, no copy needed');
});
