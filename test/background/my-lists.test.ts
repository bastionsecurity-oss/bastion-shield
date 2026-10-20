// Imported filter lists ("My lists"): parsing, limits, storage, downloads,
// daily updates and the allowCustomLists policy.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkListText,
  countFilterLines,
  freeSlot,
  isUpdateDue,
  listTitle,
  MyListsService,
  normalizeListUrl,
  parseListTitle,
  sameTitle,
  sanitizeMyLists,
  compiledKey,
  textKey,
} from '../../src/background/my-lists.ts';
import type { FetchFn } from '../../src/background/my-lists.ts';
import { compileAllCustom } from '../../src/background/custom.ts';
import { lockedPaths, myListsLocked, sanitizeManaged } from '../../src/background/settings.ts';
import { listForRule } from '../../src/background/activity.ts';
import { MY_LISTS, RULE_ID, STORAGE } from '../../src/shared/constants.ts';
import type { BuildMeta, MyListMeta } from '../../src/shared/types.ts';

const LIST = '[Adblock Plus 2.0]\n! Title: Swiss extras\n! Expires: 1 day\n||ads.muster.ch^\nmuster.ch##.banner\n';
const META = { lists: [], rulesetToList: {}, redirectResources: {} } as unknown as BuildMeta;
const DAY = MY_LISTS.UPDATE_AFTER_MS;

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

interface FakeReply {
  status?: number;
  body?: string;
  headers?: Record<string, string>;
}

function fakeFetch(replies: Record<string, FakeReply | ((init: RequestInit) => FakeReply)>) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fn: FetchFn = async (url, init) => {
    calls.push({ url, init });
    const r = replies[url];
    if (!r) throw new TypeError('Failed to fetch');
    const reply = typeof r === 'function' ? r(init) : r;
    return new Response(reply.status === 304 ? null : (reply.body ?? ''), { status: reply.status ?? 200, headers: reply.headers });
  };
  return { fn, calls };
}

function service(replies: Record<string, FakeReply | ((init: RequestInit) => FakeReply)> = {}) {
  const storage = memoryStorage();
  const fetch = fakeFetch(replies);
  let now = 1_000_000;
  let seq = 0;
  const svc = new MyListsService({
    storage,
    fetch: fetch.fn,
    now: () => now,
    // Deterministic ids: "aaaaaaaaaa", "bbbbbbbbbb", ...
    random: () => {
      const v = (Math.floor(seq / 10) % 26) / 36 + 0.0001;
      seq++;
      return v;
    },
  });
  return { svc, storage, fetch, advance: (ms: number) => (now += ms), now: () => now };
}

// --- pure helpers ------------------------------------------------------------

test('title: from the list header, else the file name, else the address', () => {
  assert.equal(parseListTitle(LIST), 'Swiss extras');
  assert.equal(parseListTitle('# Title: Hosts list\n0.0.0.0 a.ch\n'), 'Hosts list');
  assert.equal(parseListTitle('||a.ch^\n'), null);
  assert.equal(listTitle('||a.ch^\n', 'C:\\Users\\me\\Downloads\\my-blocklist.txt'), 'my-blocklist');
  assert.equal(listTitle('||a.ch^\n', 'raw.example.org › list.txt'), 'raw.example.org › list');
});

test('only https addresses without credentials are accepted', () => {
  assert.equal(normalizeListUrl(' https://example.org/list.txt#x '), 'https://example.org/list.txt');
  for (const bad of ['http://example.org/l.txt', 'https://u:p@example.org/l.txt', 'file:///c:/l.txt', 'javascript:alert(1)', '', 'not a url', 42, `https://a.ch/${'x'.repeat(3000)}`]) {
    assert.equal(normalizeListUrl(bad), null, String(bad).slice(0, 30));
  }
});

test('list text: HTML pages, binary data and comment-only files are refused', () => {
  assert.equal(checkListText(LIST), null);
  assert.equal(checkListText('0.0.0.0 tracker.example\n'), null);
  assert.equal(checkListText('<!DOCTYPE html><html><body>404</body></html>'), 'not-a-list');
  assert.equal(checkListText('\uFEFF  <html>'), 'not-a-list');
  assert.equal(checkListText('{"rules":[]}'), 'not-a-list');
  assert.equal(checkListText('a\u0000b'), 'not-a-list');
  assert.equal(checkListText('! Title: nothing\n! only comments\n\n'), 'empty');
  assert.equal(checkListText('# hosts header\n# only comments\n'), 'empty');
  assert.equal(checkListText('x'.repeat(MY_LISTS.MAX_BYTES + 1)), 'too-large');
});

test('list text: a list of generic cosmetic filters only is a list', () => {
  assert.equal(checkListText('! Title: Annoyances\n##.cookie-banner\n##.newsletter-popup\n'), null);
  assert.equal(checkListText('#@#.ok\n#?#div:has-text(Ad)\n'), null);
});

test('filter count: filter lines, not comments, headers or merged DNR rules', () => {
  const text = '[Adblock Plus 2.0]\n! Title: X\n# hosts comment\n\n||a.ch^\n||b.ch^\n0.0.0.0 c.ch\n##.ad\nmuster.ch#@#.ok\n#?#div:has-text(Ad)\n';
  assert.equal(countFilterLines(text), 6);
});

test('slots, same title and update due', () => {
  assert.equal(freeSlot([]), 0);
  assert.equal(freeSlot([{ slot: 0 }, { slot: 2 }]), 1);
  assert.equal(freeSlot(Array.from({ length: MY_LISTS.MAX }, (_, slot) => ({ slot }))), -1);
  const l = { id: 'aaaaaaaaaa', slot: 0, title: 'Swiss Extras ', source: 'url', url: 'https://a.ch/l.txt', enabled: true, autoUpdate: true, added: 0, updated: 0, checked: 0, bytes: 1 } as MyListMeta;
  assert.equal(sameTitle([l], 'swiss extras')?.id, 'aaaaaaaaaa');
  assert.equal(sameTitle([l], 'other'), undefined);
  assert.equal(isUpdateDue(l, DAY - 1), false);
  assert.equal(isUpdateDue(l, DAY), true);
  assert.equal(isUpdateDue({ ...l, autoUpdate: false }, DAY * 9), false);
  assert.equal(isUpdateDue({ ...l, enabled: false }, DAY * 9), false);
  assert.equal(isUpdateDue({ ...l, source: 'file' }, DAY * 9), false);
});

test('stored index: broken entries, duplicate ids and slots are dropped', () => {
  const ok = { id: 'aaaaaaaaaa', slot: 0, title: 'A', source: 'file', enabled: true };
  const lists = sanitizeMyLists([
    ok,
    { ...ok, title: 'dup id' },
    { ...ok, id: 'bbbbbbbbbb', title: 'dup slot' },
    { id: 'BAD', slot: 1, title: 'x', source: 'file' },
    { id: 'cccccccccc', slot: 99, source: 'file' },
    { id: 'dddddddddd', slot: 1, source: 'url', url: 'http://insecure.ch/l.txt' },
    { id: 'eeeeeeeeee', slot: 2, source: 'url', url: 'https://ok.ch/l.txt', autoUpdate: false, enabled: false },
    'garbage',
  ]);
  assert.deepEqual(
    lists.map((l) => [l.id, l.slot, l.enabled, l.autoUpdate]),
    [
      ['aaaaaaaaaa', 0, true, false],
      ['eeeeeeeeee', 2, false, false],
    ],
  );
  assert.deepEqual(sanitizeMyLists(null), []);
});

// --- service -------------------------------------------------------------------

test('a file becomes a list: stored, enabled, titled from its header, survives a reload', async () => {
  const { svc, storage } = service();
  const r = await svc.add({ file: { name: 'extras.txt', text: LIST } });
  assert.ok('list' in r);
  assert.equal(r.list.title, 'Swiss extras');
  assert.equal(r.list.source, 'file');
  assert.equal(r.list.fileName, 'extras.txt');
  assert.equal(r.list.enabled, true);
  assert.equal(r.list.autoUpdate, false);
  assert.equal(storage.data.get(textKey(r.list.id)), LIST);
  const again = new MyListsService({ storage, fetch: async () => new Response(''), now: () => 0 });
  await again.load();
  assert.deepEqual(again.enabled(), [{ id: r.list.id, slot: 0, text: LIST, stamp: `${r.list.updated}:${LIST.length}` }]);
});

test('bad files and the list limit are reported, nothing is stored', async () => {
  const { svc, storage } = service();
  assert.deepEqual(await svc.add({ file: { name: 'page.html', text: '<html></html>' } }), { error: 'not-a-list' });
  assert.equal(storage.data.size, 0);
  for (let i = 0; i < MY_LISTS.MAX; i++) await svc.add({ file: { name: `l${i}.txt`, text: `||l${i}.ch^` } });
  assert.equal(svc.all().length, MY_LISTS.MAX);
  assert.deepEqual(await svc.add({ file: { name: 'one-more.txt', text: '||x.ch^' } }), { error: 'too-many' });
});

test('replace keeps id, slot, title and on/off state; a file turns a web list into a file list', async () => {
  const url = 'https://lists.example.org/extras.txt';
  const { svc } = service({ [url]: { body: LIST, headers: { etag: '"v1"' } } });
  const added = await svc.add({ url });
  assert.ok('list' in added);
  await svc.set(added.list.id, { enabled: false });
  const r = await svc.add({ file: { name: 'local.txt', text: '! Title: Renamed\n||other.ch^\n' } }, added.list.id);
  assert.ok('list' in r);
  assert.equal(r.list.id, added.list.id);
  assert.equal(r.list.slot, added.list.slot);
  assert.equal(r.list.title, 'Swiss extras', 'the title stays; only the contents change');
  assert.equal(r.list.enabled, false);
  assert.equal(r.list.source, 'file');
  assert.equal(r.list.url, undefined);
  assert.equal(r.list.etag, undefined);
  assert.equal(r.list.autoUpdate, false);
  assert.equal(svc.text(added.list.id), '! Title: Renamed\n||other.ch^\n');
  assert.equal(svc.all().length, 1);
  assert.deepEqual(await svc.add({ file: { name: 'x.txt', text: '||x.ch^' } }, 'zzzzzzzzzz'), { error: 'not-found' });
});

test('web address: downloaded without credentials, duplicates and HTML answers refused', async () => {
  const url = 'https://lists.example.org/extras.txt';
  const { svc, fetch } = service({
    [url]: { body: LIST },
    'https://login.example.org/list.txt': { body: '<!doctype html><title>Sign in</title>' },
    'https://gone.example.org/list.txt': { status: 404 },
  });
  const r = await svc.add({ url });
  assert.ok('list' in r);
  assert.equal(r.list.source, 'url');
  assert.equal(r.list.autoUpdate, true);
  assert.equal(fetch.calls[0].init.credentials, 'omit');
  assert.deepEqual(await svc.add({ url }), { error: 'duplicate-url' });
  assert.deepEqual(await svc.add({ url: 'https://login.example.org/list.txt' }), { error: 'not-a-list' });
  assert.deepEqual(await svc.add({ url: 'https://gone.example.org/list.txt' }), { error: 'fetch-failed', detail: 'HTTP 404' });
  assert.deepEqual(await svc.add({ url: 'http://lists.example.org/extras.txt' }), { error: 'invalid-url' });
  assert.equal(svc.all().length, 1);
});

test('daily update: conditional request, unchanged lists cost nothing, errors are kept on the list', async () => {
  const url = 'https://lists.example.org/extras.txt';
  let body = LIST;
  let status = 200;
  const { svc, fetch, advance } = service({
    [url]: (init) => {
      const h = init.headers as Record<string, string>;
      if (status !== 200) return { status };
      if (h['If-None-Match'] === '"v1"' && body === LIST) return { status: 304 };
      return { body, headers: { etag: body === LIST ? '"v1"' : '"v2"' } };
    },
  });
  const r = await svc.add({ url });
  assert.ok('list' in r);
  assert.equal(await svc.updateDue(), false, 'not due yet');
  assert.equal(fetch.calls.length, 1);

  advance(DAY);
  assert.equal(await svc.updateDue(), false, '304: nothing changed');
  assert.equal(fetch.calls.length, 2);
  assert.equal((fetch.calls[1].init.headers as Record<string, string>)['If-None-Match'], '"v1"');

  advance(DAY);
  body = `${LIST}||new.example^\n`;
  assert.equal(await svc.updateDue(), true);
  assert.equal(svc.text(r.list.id), body);
  assert.equal(svc.get(r.list.id)?.etag, '"v2"');

  advance(DAY);
  status = 503;
  assert.equal(await svc.updateDue(), false);
  assert.match(svc.get(r.list.id)?.error ?? '', /HTTP 503/);
  assert.equal(svc.text(r.list.id), body, 'a failed download keeps the last good copy');

  await svc.set(r.list.id, { autoUpdate: false });
  advance(DAY * 3);
  const before = fetch.calls.length;
  assert.equal(await svc.updateDue(), false);
  assert.equal(fetch.calls.length, before, 'auto-update off: never fetched');
});

test('remove deletes the text and frees the slot', async () => {
  const { svc, storage } = service();
  const a = await svc.add({ file: { name: 'a.txt', text: '||a.ch^' } });
  const b = await svc.add({ file: { name: 'b.txt', text: '||b.ch^' } });
  assert.ok('list' in a && 'list' in b);
  assert.deepEqual(await svc.remove(a.list.id), { ok: true });
  assert.equal(storage.data.has(textKey(a.list.id)), false);
  const c = await svc.add({ file: { name: 'c.txt', text: '||c.ch^' } });
  assert.ok('list' in c);
  assert.equal(c.list.slot, a.list.slot, 'the freed slot is reused');
  assert.deepEqual(
    (storage.data.get(STORAGE.MY_LISTS) as MyListMeta[]).map((l) => l.id),
    [b.list.id, c.list.id],
  );
});

test('another worker (incognito) changing the index reloads; our own echo does not', async () => {
  const { svc, storage } = service();
  const a = await svc.add({ file: { name: 'a.txt', text: '||a.ch^' } });
  assert.ok('list' in a);
  const echo = { [STORAGE.MY_LISTS]: { newValue: storage.data.get(STORAGE.MY_LISTS) } };
  assert.equal(await svc.onStorageChanged(echo), false);
  const other = structuredClone(storage.data.get(STORAGE.MY_LISTS) as MyListMeta[]);
  other[0].enabled = false;
  storage.data.set(STORAGE.MY_LISTS, other);
  assert.equal(await svc.onStorageChanged({ [STORAGE.MY_LISTS]: { newValue: other } }), true);
  assert.deepEqual(svc.enabled(), []);
});

test('regression: echoes of our own writes (text key, late index echoes) never drop a new list', async () => {
  const { svc, storage } = service();
  const a = await svc.add({ file: { name: 'a.txt', text: '||a.ch^' } });
  const echoA = storage.data.get(STORAGE.MY_LISTS);
  const b = await svc.add({ file: { name: 'b.txt', text: '||b.ch^' } });
  assert.ok('list' in a && 'list' in b);
  // The text key's own event and both index echoes arrive after the second add.
  assert.equal(await svc.onStorageChanged({ [textKey(b.list.id)]: { newValue: '||b.ch^' } }), false);
  assert.equal(await svc.onStorageChanged({ [STORAGE.MY_LISTS]: { newValue: echoA } }), false);
  assert.equal(await svc.onStorageChanged({ [STORAGE.MY_LISTS]: { newValue: storage.data.get(STORAGE.MY_LISTS) } }), false);
  assert.deepEqual(
    svc.enabled().map((l) => l.text),
    ['||a.ch^', '||b.ch^'],
  );
});

test('downloads run outside the change queue: switching a list never waits for a slow server', async () => {
  const url = 'https://slow.example.org/list.txt';
  let release: () => void = () => undefined;
  let slow = false;
  const storage = memoryStorage();
  let now = 1_000_000;
  const svc = new MyListsService({
    storage,
    fetch: async () => {
      if (slow) await new Promise<void>((r) => (release = r));
      return new Response(LIST, { status: 200 });
    },
    now: () => now,
  });
  const added = await svc.add({ url });
  const other = await svc.add({ file: { name: 'b.txt', text: '||b.ch^' } });
  assert.ok('list' in added && 'list' in other);
  now += DAY;
  slow = true;
  const due = svc.updateDue();
  assert.equal(svc.updateDue(), due, 'a second alarm joins the running update');
  // The update is waiting for the server; a switch goes through at once.
  const switched = await svc.set(other.list.id, { enabled: false });
  assert.ok('list' in switched && switched.list.enabled === false);
  release();
  assert.equal(await due, false, 'same text: nothing changed');
  assert.equal(svc.get(added.list.id)?.checked, now);
  assert.equal(svc.get(other.list.id)?.enabled, false, 'the update did not undo the switch');
});

test('a failed text write leaves the list as it was (no validators for contents that were not stored)', async () => {
  const url = 'https://lists.example.org/extras.txt';
  let body = LIST;
  const { svc, storage, advance } = service({ [url]: () => ({ body, headers: { etag: body === LIST ? '"v1"' : '"v2"' } }) });
  const r = await svc.add({ url });
  assert.ok('list' in r);
  const before = structuredClone(svc.get(r.list.id));
  const set = storage.set;
  storage.set = async (items) => {
    if (Object.keys(items).some((k) => k.startsWith(STORAGE.MY_LIST_PREFIX))) throw new Error('disk full');
    return set.call(storage, items);
  };
  advance(DAY);
  body = `${LIST}||new.example^\n`;
  assert.equal(await svc.updateDue(), false, 'the failed list is skipped, the run goes on');
  assert.deepEqual(svc.get(r.list.id), before, 'etag, size and dates unchanged');
  assert.equal(svc.text(r.list.id), LIST);
  storage.set = set;
  // The old validator was kept, so the next update downloads the new text again.
  assert.equal(await svc.updateDue(), true);
  assert.equal(svc.text(r.list.id), body);
  assert.equal(svc.get(r.list.id)?.etag, '"v2"');
});

test('compiled copies are reused only for the same text and build', async () => {
  const { svc, storage } = service();
  const r = await svc.add({ file: { name: 'a.txt', text: LIST } });
  assert.ok('list' in r);
  const [input] = svc.enabled();
  const compiled = compileAllCustom('', [], META, [input]).my[0].compiled;
  await svc.saveCompiled(input, 'v1|t1', compiled);
  assert.ok(storage.data.has(compiledKey(r.list.id)));
  const back = await svc.loadCompiled('v1|t1');
  assert.equal(back.length, 1);
  assert.deepEqual(back[0].compiled, JSON.parse(JSON.stringify(compiled)));
  assert.deepEqual(await svc.loadCompiled('v2|t1'), [], 'another extension build recompiles');
  await svc.add({ file: { name: 'a.txt', text: '||changed.ch^' } }, r.list.id);
  assert.deepEqual(await svc.loadCompiled('v1|t1'), [], 'a new text recompiles');
  await svc.remove(r.list.id);
  assert.equal(storage.data.has(compiledKey(r.list.id)), false, 'removed with the list');
});

test('imported lists may not carry @@…$important (it would outrank every $important block)', () => {
  const lists = [{ id: 'cccccccccc', slot: 1, text: '@@||tracker.example^$important\n@@||phish.example^$document,important\n||ok.example^\n' }];
  const c = compileAllCustom('@@||mine.example^$important', [], META, lists);
  const my = c.my[0].compiled;
  assert.equal(my.errors.length, 2);
  assert.ok(my.errors.every((e) => e.reason === 'invalid-option'));
  assert.ok(my.rules.every((r) => r.action.type === 'block'), 'only the plain block is left');
  assert.ok(c.user.rules.some((r) => r.action.type === 'allow' && r.priority === 50), "the user's own important exception still works");
});

// --- compile, attribution, policy ----------------------------------------------

test('imported lists compile like user filters and are cached per text', () => {
  const lists = [{ id: 'aaaaaaaaaa', slot: 3, text: LIST }];
  const c = compileAllCustom('', [], META, lists);
  assert.equal(c.my.length, 1);
  assert.equal(c.my[0].slot, 3);
  assert.ok(c.my[0].compiled.rules.length >= 1);
  assert.ok(c.cosmetic.specific.length >= 1, 'cosmetic filters join the custom cosmetics');
  const again = compileAllCustom('||u.ch^', [], META, lists);
  assert.equal(again.my[0].compiled, c.my[0].compiled, 'unchanged text is not recompiled');
});

test('matches in the imported-list rule range are attributed to «My lists»', () => {
  assert.equal(listForRule('_dynamic', RULE_ID.MY_LISTS_START + 2 * MY_LISTS.SLOT_SIZE + 5, {}), 'my-lists');
  assert.equal(RULE_ID.MY_LISTS_START + MY_LISTS.MAX * MY_LISTS.SLOT_SIZE - 1, RULE_ID.MY_LISTS_END, 'slots fill the range exactly');
  assert.ok(RULE_ID.MY_LISTS_END < RULE_ID.SITES_DISABLED);
});

test('allowCustomLists: false or lockSettings forbids imported lists; an explicit true reopens them', () => {
  assert.equal(myListsLocked({}), false);
  assert.equal(myListsLocked({ allowCustomLists: false }), true);
  assert.equal(myListsLocked({ lockSettings: true }), true);
  assert.equal(myListsLocked({ lockSettings: true, allowCustomLists: true }), false);
  assert.ok(lockedPaths({ allowCustomLists: false }, []).includes('myLists'));
  // Registry-style values from Intune (0/1, strings) are understood.
  assert.equal(sanitizeManaged({ allowCustomLists: 0 }).allowCustomLists, false);
  assert.equal(sanitizeManaged({ allowCustomLists: 'true' }).allowCustomLists, true);
  assert.ok(!lockedPaths({}, []).includes('myLists'));
});
