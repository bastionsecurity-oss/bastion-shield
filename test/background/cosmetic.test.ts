// Tests for cosmetic filtering in the service worker: candidate host keys,
// merging shard entries with list masks, exceptions and flags, CSS assembly,
// generic token lookup and the service's insertCSS flow (src/background/cosmetic.ts).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
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
  EMPTY_CUSTOM,
  genericHighCopies,
  genericHighExcludedSet,
  genericLookupFromText,
  genericSelectorsForTokens,
  hostKeyCandidates,
  hostSelectorsByList,
  isVettedSearchEngine,
  resolveHostCosmetic,
  softHighGeneric,
  softPolicy,
  splitGenericSelectors,
  withOverride,
  withoutSelectors,
} from '../../src/background/cosmetic.ts';
import type { CosmeticConfig, CosmeticTarget, CustomCosmetic, TabCosmeticOverride } from '../../src/background/cosmetic.ts';

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

test('custom filters of imported lists are looked up by host and token, in filter order, each once', () => {
  // Thousands of entries (an imported EasyList): only the matching ones matter, in their own order.
  const specific: CustomCosmetic['specific'] = [];
  for (let i = 0; i < 5000; i++) specific.push({ kind: 0, hosts: [`site${i}.ch`], excludedHosts: [], payload: `.s${i}`, raw: '' });
  specific.push({ kind: 0, hosts: ['example.com', 'www.example.com'], excludedHosts: [], payload: '.both', raw: '' });
  specific.unshift({ kind: 0, hosts: ['example.com'], excludedHosts: [], payload: '.first', raw: '' });
  const generic: CustomCosmetic['generic'] = [
    { selector: '.b2', token: '.b', excludedHosts: [], raw: '' },
    { selector: '.a1', token: '.a', excludedHosts: [], raw: '' },
    { selector: '.b1', token: '.b', excludedHosts: ['www.example.com'], raw: '' },
  ];
  const custom: CustomCosmetic = { specific, generic };
  const cands = hostKeyCandidates('www.example.com');
  const host = resolveHostCosmetic([], A, cands, custom);
  assert.deepEqual(host.hide, ['.first', '.both'], 'the entry listed under two candidate hosts comes once');
  assert.deepEqual(genericSelectorsForTokens(null, ['.a', '.b'], A, host, cands, custom), ['.b2', '.a1']);
  assert.deepEqual(resolveHostCosmetic([], A, hostKeyCandidates('site4321.ch'), custom).hide, ['.s4321']);
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

function makeService(
  shards: Record<string, CosmeticShard>,
  opts: {
    off?: string[];
    generic?: GenericIndex;
    meta?: CosmeticMeta;
    high?: Record<string, string[]>;
    soft?: 'b';
    aggressive?: string[];
    override?: (tabId: number) => Promise<TabCosmeticOverride | null>;
  } = {},
) {
  const inserted: { target: CosmeticTarget; css: string }[] = [];
  const loads: string[] = [];
  const meta: CosmeticMeta = opts.meta ?? { shards: 256, genericHighCss: {}, genericHighExcludedHosts: {}, genericHighSelectorsFile: 'cosmetic/generic-high.json' };
  const cfg: CosmeticConfig = {
    enabledMask: A | B,
    enabledListIds: new Set(['a', 'b']),
    listBits: new Map([
      ['a', 0],
      ['b', 1],
    ]),
    softMask: opts.soft ? B : 0,
    softListIds: new Set(opts.soft ? ['b'] : []),
    modeOf: (h) => ((opts.aggressive ?? []).includes(h) ? 'aggressive' : 'standard'),
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
    ...(opts.override ? { tabOverride: opts.override } : {}),
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

// --- bisect override (nerd-bisect.ts, cosmetic phase) -------------------------

test('bisect override: lists off clear their mask bits, ids and (custom) the custom filters', () => {
  const custom: CustomCosmetic = { specific: [{ kind: 0, hosts: ['example.com'], excludedHosts: [], payload: '.mine', raw: 'example.com##.mine' }], generic: [] };
  const cfg: CosmeticConfig = {
    enabledMask: A | B,
    enabledListIds: new Set(['a', 'b']),
    listBits: new Map([
      ['a', 0],
      ['b', 1],
    ]),
    softMask: B,
    softListIds: new Set(['b']),
    modeOf: () => 'standard',
    deAmp: false,
    custom,
    isOff: () => false,
  };
  assert.equal(withOverride(cfg, { lists: [], selectors: ['.x'] }), cfg);
  const off = withOverride(cfg, { lists: ['a'], selectors: [] });
  assert.equal(off.enabledMask, B);
  assert.deepEqual(Array.from(off.enabledListIds), ['b']);
  assert.equal(off.custom, custom);
  const noCustom = withOverride(cfg, { lists: ['custom', 'b'], selectors: [] });
  assert.equal(noCustom.enabledMask, A);
  assert.deepEqual(noCustom.custom, { specific: [], generic: [] });
  assert.equal(off.softMask, B, 'a hard list off keeps the soft lists');
  assert.equal(noCustom.softMask, 0, 'a soft list off leaves the soft mask');
  assert.deepEqual(Array.from(noCustom.softListIds), []);
});

test('bisect override: selectors off act like exceptions for hide, style and procedural entries', () => {
  const proc = JSON.stringify({ raw: 'div:has-text(Werbung)', selector: 'div', tasks: [['has-text', 'Werbung']] });
  const host = resolveHostCosmetic([[[0, '.ad', A], [0, '.keep', A], [3, '.x { color: red }', A], [2, proc, A]]], A, ['example.com']);
  const r = withoutSelectors(host, new Set(['.ad', '.x { color: red }', 'div:has-text(Werbung)']));
  assert.deepEqual(r.hide, ['.keep']);
  const soft = withoutSelectors(resolveHostCosmetic([[[0, '.ad', B], [0, '.keep', B]]], A | B, ['example.com'], undefined, B), new Set(['.ad']));
  assert.deepEqual(soft.soft, ['.keep'], 'soft selectors too');
  assert.deepEqual(r.styles, []);
  assert.deepEqual(r.procedural, []);
  assert.equal(withoutSelectors(host, new Set()), host);
});

test('bisect candidates: host-specific selectors in effect, per enabled list', () => {
  const proc = JSON.stringify({ raw: 'p:has-text(Anzeige)', selector: 'p', tasks: [['has-text', 'Anzeige']] });
  const host: CosmeticHostEntry[] = [
    [0, 'section aside:has(> div[data-ad-unit-id])', A | B],
    [0, '.only-a', A],
    [0, '.excepted', B],
    [3, '.x { color: red }', B],
    [2, proc, A],
    [0, '.disabled-list', C],
  ];
  const parent: CosmeticHostEntry[] = [[1, '.excepted', A]];
  const custom: CustomCosmetic = { specific: [{ kind: 0, hosts: ['20min.ch'], excludedHosts: [], payload: '.mine', raw: '20min.ch##.mine' }], generic: [] };
  const bits = new Map([
    ['a', 0],
    ['b', 1],
    ['c', 2],
  ]);
  const by = hostSelectorsByList([host, parent], A | B, ['www.20min.ch', '20min.ch'], custom, bits);
  assert.deepEqual(by.get('a'), ['section aside:has(> div[data-ad-unit-id])', '.only-a', 'p:has-text(Anzeige)']);
  assert.deepEqual(by.get('b'), ['section aside:has(> div[data-ad-unit-id])', '.x { color: red }']);
  assert.equal(by.has('c'), false, 'disabled lists have no candidates');
  assert.deepEqual(by.get('custom'), ['.mine']);
});

test('service: a tab with a bisect override gets CSS without the switched-off lists and selectors, others are unaffected', async () => {
  const shards = shardsFor({ 'example.com': [[0, '.from-a', A], [0, '.from-b', B], [0, '.also-b', B]] });
  const overrides = new Map<number, TabCosmeticOverride>([
    [1, { lists: ['a'], selectors: [] }],
    [2, { lists: [], selectors: ['.from-b'] }],
  ]);
  const { svc } = makeService(shards, { override: async (tabId) => overrides.get(tabId) ?? null });
  const frame = async (tabId: number) =>
    (await svc.onFrame({ type: 'cosmetic:frame', url: 'https://example.com/' }, { tabId, frameId: 0, tabUrl: 'https://example.com/' })).css;
  const normal = await frame(3);
  assert.match(normal, /\.from-a/);
  assert.match(normal, /\.from-b/);
  const listsOff = await frame(1);
  assert.doesNotMatch(listsOff, /\.from-a/);
  assert.match(listsOff, /\.from-b/);
  const selOff = await frame(2);
  assert.match(selOff, /\.from-a/);
  assert.doesNotMatch(selOff, /\.from-b/);
  assert.match(selOff, /\.also-b/);
  // The overridden results never reach the shared host cache.
  assert.match(await frame(3), /\.from-a/);
  assert.deepEqual(Object.fromEntries(await svc.hostSelectors('example.com')), { a: ['.from-a'], b: ['.from-b', '.also-b'] });
});

test('service: generic token CSS follows the lists a bisect switched off', async () => {
  const { svc } = makeService({}, {
    generic: { tokens: { '#banner': [['#banner', A]], '#promo': [['#promo', B]] } },
    override: async (tabId) => (tabId === 1 ? { lists: ['a'], selectors: [] } : null),
  });
  const sender = (tabId: number) => ({ tabId, frameId: 0, tabUrl: 'https://example.com/' });
  const msg = { type: 'cosmetic:tokens' as const, url: 'https://example.com/', tokens: ['#banner', '#promo'] };
  assert.equal((await svc.onTokens(msg, sender(1))).css, '#promo{display:none!important}');
  assert.match((await svc.onTokens(msg, sender(2))).css, /#banner/);
});

// --- Standard-mode soft selectors (ARCHITECTURE §5.2.8) ----------------------

test('soft selectors: only first-party-protected lists, never custom filters', () => {
  const entries: CosmeticHostEntry[] = [
    [0, '.only-b', B],
    [0, '.a-and-b', A | B],
    [0, '.only-a', A],
    [0, '.b-and-disabled', B | C],
    [0, '.custom', B],
  ];
  const custom: CustomCosmetic = { specific: [{ kind: 0, payload: '.custom', hosts: ['example.com'], excludedHosts: [], raw: 'example.com##.custom' }], generic: [] };
  const r = resolveHostCosmetic([entries], A | B, ['example.com'], custom, B);
  assert.deepEqual(r.hide.sort(), ['.a-and-b', '.custom', '.only-a']);
  assert.deepEqual(r.soft.sort(), ['.b-and-disabled', '.only-b']);
  const all = resolveHostCosmetic([entries], A | B, ['example.com'], custom);
  assert.deepEqual(all.soft, [], 'without a soft mask everything is hard');
  const ex = resolveHostCosmetic([[...entries, [1, '.only-b', A]]], A | B, ['example.com'], EMPTY_CUSTOM, B);
  assert.ok(!ex.soft.includes('.only-b'), 'exceptions apply to soft selectors');
});

test('soft selectors: generic tokens split the same way', () => {
  const index: GenericIndex = { tokens: { '.x': [['.x', B], ['.x.y', A | B], ['div.x', A]] } };
  const custom: CustomCosmetic = { specific: [], generic: [{ selector: '.x .c', token: '.x', excludedHosts: [], raw: '##.x .c' }] };
  const r = splitGenericSelectors(index, ['.x'], A | B, { exceptions: new Set() }, ['example.com'], custom, B);
  assert.deepEqual(r.hard.sort(), ['.x .c', '.x.y', 'div.x']);
  assert.deepEqual(r.soft, ['.x']);
  assert.deepEqual(genericSelectorsForTokens(index, ['.x'], A | B, { exceptions: new Set() }, ['example.com'], custom).sort(), ['.x', '.x .c', '.x.y', 'div.x']);
});

test('soft selectors: highly generic CSS of protected lists, minus exceptions', () => {
  const high = { a: ['.ha'], b: ['.hb', '.hx'], c: ['.hc'] };
  assert.deepEqual(softHighGeneric(high, new Set(['b']), { exceptions: new Set(['.hx']), genericAllowed: true }), ['.hb']);
  assert.deepEqual(softHighGeneric(high, new Set(['b']), { exceptions: new Set(), genericAllowed: false }), []);
  assert.deepEqual(softHighGeneric(null, new Set(['b']), { exceptions: new Set(), genericAllowed: true }), []);
});

test('soft policy follows Brave: aggressive, cross-host frames and YouTube hide; search engines drop', () => {
  assert.equal(softPolicy('www.20min.ch', 'www.20min.ch', 'standard'), 'soft');
  assert.equal(softPolicy('www.20min.ch', 'www.20min.ch', 'aggressive'), 'hard');
  assert.equal(softPolicy('ads.example.net', 'www.20min.ch', 'standard'), 'hard');
  assert.equal(softPolicy('m.20min.ch', 'www.20min.ch', 'standard'), 'hard', 'another origin, even same-site');
  assert.equal(softPolicy('www.youtube.com', 'www.youtube.com', 'standard'), 'hard');
  assert.equal(softPolicy('www.google.ch', 'www.google.ch', 'standard'), 'drop');
  assert.equal(softPolicy('www.google.co.uk', 'www.google.co.uk', 'standard'), 'drop');
  assert.equal(softPolicy('duckduckgo.com', 'duckduckgo.com', 'standard'), 'drop');
  assert.equal(softPolicy('search.brave.com', 'search.brave.com', 'aggressive'), 'hard');
  assert.equal(softPolicy('www.google.ch', null, 'standard'), 'drop');
  assert.equal(isVettedSearchEngine('maps.google.com'), true);
  assert.equal(isVettedSearchEngine('googleads.example.com'), false);
  assert.equal(isVettedSearchEngine('bing.example.com'), false);
});

test('service: Standard mode sends soft selectors apart, Aggressive mode hides them', async () => {
  const meta: CosmeticMeta = {
    shards: 256,
    genericHighCss: { a: 'cosmetic/generic-high/a.css', b: 'cosmetic/generic-high/b.css' },
    genericHighExcludedHosts: { a: [], b: ['example.com'] },
    genericHighSelectorsFile: 'cosmetic/generic-high.json',
  };
  const high = { a: ['.ha'], b: ['.hb'] };
  const shards = shardsFor({ 'example.com': [[0, '.hard', A], [0, '.soft', B]], 'google.ch': [[0, '.serp-ad', B], [0, '.serp-hard', A]] });
  const { svc, inserted } = makeService(shards, { meta, high, soft: 'b', aggressive: ['agg.example.com'], generic: { tokens: { '.t': [['.t', B], ['.t2', A]] } } });

  const std = await svc.onFrame({ type: 'cosmetic:frame', url: 'https://www.example.com/' }, { tabId: 1, frameId: 0, tabUrl: 'https://www.example.com/' });
  assert.match(std.css, /\.hard/);
  assert.doesNotMatch(std.css, /\.soft|\.hb/);
  assert.doesNotMatch(std.css, /\.ha\b/, "list a's highly generic CSS is registered; example.com is only excluded by soft list b");
  assert.deepEqual(std.soft?.sort(), ['.hb', '.soft']);
  assert.equal(std.site, 'example.com');
  assert.doesNotMatch(inserted.at(-1)!.css, /\.soft/, 'soft selectors never reach insertCSS (USER origin cannot be undone)');

  const agg = await svc.onFrame({ type: 'cosmetic:frame', url: 'https://agg.example.com/' }, { tabId: 1, frameId: 0, tabUrl: 'https://agg.example.com/' });
  assert.match(agg.css, /\.soft/);
  assert.match(agg.css, /\.hb/);
  assert.equal(agg.soft, undefined);

  const sub = await svc.onFrame({ type: 'cosmetic:frame', url: 'https://www.example.com/frame' }, { tabId: 1, frameId: 3, tabUrl: 'https://news.ch/' });
  assert.match(sub.css, /\.soft/, 'a frame of another site hides like Aggressive mode');
  assert.equal(sub.soft, undefined);

  const serp = await svc.onFrame({ type: 'cosmetic:frame', url: 'https://www.google.ch/search' }, { tabId: 1, frameId: 0, tabUrl: 'https://www.google.ch/search' });
  assert.match(serp.css, /\.serp-hard/);
  assert.doesNotMatch(serp.css, /\.serp-ad|\.hb/);
  assert.equal(serp.soft, undefined, 'search engines: soft selectors are not applied at all');

  const tok = await svc.onTokens({ type: 'cosmetic:tokens', url: 'https://www.example.com/', tokens: ['.t'] }, { tabId: 1, frameId: 0, tabUrl: 'https://www.example.com/' });
  assert.equal(tok.css, '.t2{display:none!important}');
  assert.deepEqual(tok.soft, ['.t']);
  const tokAgg = await svc.onTokens({ type: 'cosmetic:tokens', url: 'https://agg.example.com/', tokens: ['.t'] }, { tabId: 1, frameId: 0, tabUrl: 'https://agg.example.com/' });
  assert.match(tokAgg.css, /\.t,\n\.t2|\.t2,\n\.t/);
  assert.equal(tokAgg.soft, undefined);
});
