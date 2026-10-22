// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Unit tests for the pure logic of the dashboard redesign, part A (Phase 5a):
// chart axis and peak, overview top lists and day series, activity filters
// and CSV, filter-list budget, «Meine Listen» input checks, the restore of a
// removed list and list renaming in the service worker. Run with npm test.
import test from 'node:test';
import assert from 'node:assert/strict';

const ROOT = new URL('../../src', import.meta.url).href;
const { axisLabel, niceMax, xLabelIndices, peakOf } = await import(`${ROOT}/ui/dashboard/chart.ts`);
const { topEntries, categoryEntries, hostRows, daySeries, TOP_FIRST, TOP_MAX } = await import(`${ROOT}/ui/dashboard/views/overview.ts`);
const { matches, emptyFilters, hasFilters, filterQuery, toCsv } = await import(`${ROOT}/ui/dashboard/views/activity.ts`);
const { budgetPercent } = await import(`${ROOT}/ui/dashboard/views/lists.ts`);
const { checkListFile, checkListUrl, counterText, shortName, myListErrorText } = await import(`${ROOT}/ui/dashboard/views/my-lists.ts`);
const { cleanTitle, MyListsService } = await import(`${ROOT}/background/my-lists.ts`);
const { MY_LISTS } = await import(`${ROOT}/shared/constants.ts`);

test('chart: axis labels are short, locale decimals, no grouping', () => {
  assert.equal(axisLabel(0, 'de-CH'), '0');
  assert.equal(axisLabel(750, 'de-CH'), '750');
  assert.equal(axisLabel(1500, 'de-CH'), '1.5k');
  assert.equal(axisLabel(3000, 'de-CH'), '3k');
  assert.equal(axisLabel(1_200_000, 'de-CH'), '1.2M');
  assert.equal(axisLabel(1500, 'fr-CH'), '1,5k');
});

test('chart: nice maximum, x labels and peak', () => {
  assert.equal(niceMax(0), 4);
  assert.equal(niceMax(2941), 3000);
  assert.equal(niceMax(3000), 3000);
  assert.equal(niceMax(31), 40);
  assert.deepEqual(xLabelIndices(30), [0, 7, 14, 21, 29], 'every 7th day and today, none too close to today');
  assert.deepEqual(xLabelIndices(30, true), [0, 29]);
  assert.deepEqual(xLabelIndices(1), [0]);
  assert.deepEqual(xLabelIndices(0), []);
  assert.equal(peakOf([{ value: 1 }, { value: 5, id: 'a' }, { value: 5, id: 'b' }])?.id, 'a', 'first on a tie');
  assert.equal(peakOf([{ value: 0 }]), null);
});

test('overview: top entries, categories with unattributed last, hosts cut in the middle', () => {
  assert.deepEqual(topEntries({ a: 1, b: 5, c: 0, d: 3 }, 2), [['b', 5], ['d', 3]]);
  const cats = categoryEntries({ unknown: 900, ads: 100, privacy: 300, custom: 0 }).map(([k]: [string]) => k);
  assert.deepEqual(cats, ['privacy', 'ads', 'unknown']);
  const rows = hostRows([['securepubads.g.doubleclick.net', 4209], ['x.com', 3]], 22);
  assert.equal(rows[0].label, 'secure…doubleclick.net', 'start and registrable domain stay');
  assert.equal(rows[0].title, 'securepubads.g.doubleclick.net');
  assert.ok(rows[0].label.length <= 22);
  assert.equal(rows[1].label, 'x.com');
  assert.ok(TOP_FIRST < TOP_MAX);
});

test('overview: 30 day series ends today, missing days are 0, today is quiet', () => {
  const today = new Date(2026, 9, 22, 15);
  const s = daySeries([{ day: '2026-10-21', total: 7 } as never, { day: '2026-10-22', total: 2 } as never], today);
  assert.equal(s.length, 30);
  assert.equal(s[29].value, 2);
  assert.equal(s[29].quiet, true);
  assert.equal(s[28].value, 7);
  assert.equal(s[0].value, 0);
});

test('activity: filters by host, site, either, type and kind', () => {
  const e = { t: 1, tabId: 1, frameId: 0, kind: 'blocked', url: 'https://a.tracker.com/x', host: 'a.tracker.com', type: 'script', site: '20min.ch', thirdParty: true };
  const f = emptyFilters();
  assert.equal(hasFilters(f), false);
  assert.equal(matches(e, f), true);
  assert.equal(matches(e, { ...f, any: '20min' }), true, 'panel field matches the site');
  assert.equal(matches(e, { ...f, any: 'tracker' }), true, 'panel field matches the host');
  assert.equal(matches(e, { ...f, any: 'nzz' }), false);
  assert.equal(matches(e, { ...f, site: 'blick' }), false);
  assert.equal(matches(e, { ...f, kind: 'stripped' }), false);
  assert.equal(matches(e, { ...f, type: 'script', host: 'tracker' }), true);
  assert.equal(filterQuery({ ...f, site: 'xyz-tracker.ch' }), 'xyz-tracker.ch');
  assert.equal(filterQuery({ ...f, kind: 'blocked' }), '');
  assert.equal(hasFilters({ ...f, kind: 'blocked' }), true);
});

test('activity: CSV neutralises formulas and quotes separators', () => {
  const csv = toCsv([{ t: 0, tabId: 1, frameId: 0, kind: 'blocked', url: '=cmd|x', host: 'a,b', type: 'script', site: '@s', thirdParty: false }]);
  assert.ok(csv.startsWith('﻿time,'));
  assert.ok(csv.includes(`"'=cmd|x"`) || csv.includes(`'=cmd|x`));
  assert.ok(csv.includes('"a,b"'));
  assert.ok(csv.includes(`'@s`));
});

test('lists: budget percent', () => {
  assert.equal(budgetPercent(21_480, 30_000), 72);
  assert.equal(budgetPercent(29_140, 30_000), 97);
  assert.equal(budgetPercent(5, 0), 0);
  assert.equal(budgetPercent(0, 1000), 0);
});

test('my lists: file checks (type, size, empty)', () => {
  assert.equal(checkListFile('kundenliste-export-final-v3 (1).xlsx', 2000), 'type');
  assert.equal(checkListFile('blocklist-full.txt', 14_200_000), 'size');
  assert.equal(checkListFile('leer.txt', 30, '! Title: leer\n# nur Kommentare\n\n'), 'empty');
  assert.equal(checkListFile('liste.txt', 30, '[Adblock Plus 2.0]\n||ads.ch^\n'), null);
  assert.equal(checkListFile('hosts', 30, '0.0.0.0 ads.ch\n'), null, 'no extension is fine');
  assert.equal(checkListFile('bin.txt', 30, 'PK\u0000\u0003'), 'type', 'binary content');
  assert.equal(checkListFile('a.hosts', MY_LISTS.MAX_BYTES), null, 'exactly at the limit');
});

test('my lists: address checks (scheme, length, duplicate)', () => {
  const lists = [{ url: 'https://filters.example.ch/firma.txt', title: 'Firma' }, { title: 'Datei' }];
  assert.deepEqual(checkListUrl('', lists), { code: 'empty' });
  assert.deepEqual(checkListUrl('http://a.ch/l.txt', lists), { code: 'scheme' });
  assert.deepEqual(checkListUrl('filters.example.ch/x', lists), { code: 'scheme' });
  assert.deepEqual(checkListUrl(` https://filters.example.ch/firma.txt `, lists), { code: 'duplicate', title: 'Firma' });
  assert.deepEqual(checkListUrl(`https://a.ch/${'x'.repeat(MY_LISTS.MAX_URL_LENGTH)}`, lists), { code: 'length' });
  assert.equal(checkListUrl('https://filters.example.ch/other.txt', lists), null);
});

test('my lists: counter from 80 % of the limit, short names, error texts', () => {
  assert.equal(counterText(95, 120), null);
  assert.equal(counterText(96, 120), "96 / 120");
  assert.equal(counterText(118, 120), "118 / 120");
  assert.equal(counterText(1600, 2048), null);
  assert.equal(shortName('Kurz'), 'Kurz');
  const long = shortName('x'.repeat(100), 20);
  assert.equal(long.length, 20);
  assert.ok(long.endsWith('…'));
  assert.equal(typeof myListErrorText('invalid-title'), 'string');
});

function memoryStorage() {
  const data = new Map<string, unknown>();
  return {
    data,
    async get(keys: string[]) {
      const out: Record<string, unknown> = {};
      for (const k of keys) if (data.has(k)) out[k] = structuredClone(data.get(k));
      return out;
    },
    async set(items: Record<string, unknown>) {
      for (const [k, v] of Object.entries(items)) data.set(k, structuredClone(v));
    },
    async remove(keys: string[]) {
      for (const k of keys) data.delete(k);
    },
  };
}

function service() {
  let seq = 0;
  return new MyListsService({
    storage: memoryStorage(),
    fetch: async () => {
      throw new TypeError('offline');
    },
    now: () => 1_000_000,
    random: () => ((Math.floor(seq++ / 10) % 26) / 36 + 0.0001),
  });
}

test('service: list names are cleaned and renamed', async () => {
  assert.equal(cleanTitle('  Meine\n Liste\t '), 'Meine Liste');
  assert.equal(cleanTitle('x'.repeat(200)).length, MY_LISTS.MAX_TITLE_LENGTH);
  assert.equal(cleanTitle('   '), '');
  const svc = service();
  const a = await svc.add({ file: { name: 'a.txt', text: '||a.ch^' } });
  assert.ok('list' in a);
  const r = await svc.set(a.list.id, { title: '  Firmenliste  ' });
  assert.ok('list' in r && r.list.title === 'Firmenliste');
  assert.deepEqual(await svc.set(a.list.id, { title: ' ' }), { error: 'invalid-title' });
});

test('service: a removed list comes back with its text, slot and switch state', async () => {
  const svc = service();
  const a = await svc.add({ file: { name: 'a.txt', text: '||a.ch^\n||b.ch^' } });
  assert.ok('list' in a);
  await svc.set(a.list.id, { enabled: false });
  await svc.remove(a.list.id);
  assert.equal(svc.get(a.list.id), undefined);
  const r = await svc.restore(a.list.id);
  assert.ok('list' in r);
  assert.equal(r.list.enabled, false, 'switch state kept');
  assert.equal(r.list.slot, a.list.slot, 'old slot reused');
  assert.equal(svc.text(a.list.id), '||a.ch^\n||b.ch^', 'text restored');
  assert.deepEqual(await svc.restore(a.list.id), { error: 'not-found' }, 'only once');
});

test('service: restore takes a free slot when the old one was reused', async () => {
  const svc = service();
  const a = await svc.add({ file: { name: 'a.txt', text: '||a.ch^' } });
  assert.ok('list' in a);
  await svc.remove(a.list.id);
  const b = await svc.add({ file: { name: 'b.txt', text: '||b.ch^' } });
  assert.ok('list' in b && b.list.slot === a.list.slot);
  const r = await svc.restore(a.list.id);
  assert.ok('list' in r);
  assert.notEqual(r.list.slot, b.list.slot);
});
