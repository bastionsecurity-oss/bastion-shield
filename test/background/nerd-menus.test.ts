// Tests for the nerd-mode context menu (src/background/nerd-menus.ts): the
// menu specs, the Lab deep links built from a click, and show / hide / click
// handling against a fake chrome.contextMenus.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { labHash, MAX_SELECTION, MENU, menuSpecs, NerdMenus, type MenuSpec, type NerdMenuDeps } from '../../src/background/nerd-menus.ts';
import type { MsgNerdBisect } from '../../src/shared/types.ts';

const msg = (key: string): string => `[${key}]`;
const DASH = 'chrome-extension://abc/ui/dashboard.html';

function params(hash: string): Record<string, string> {
  return Object.fromEntries(new URLSearchParams(hash.slice(hash.indexOf('?') + 1)));
}

test('menu specs: one parent for page contexts, Open Lab on the toolbar icon, ids prefixed nerd-', () => {
  const specs = menuSpecs(msg);
  assert.ok(specs.every((s) => s.id.startsWith('nerd-')));
  assert.equal(new Set(specs.map((s) => s.id)).size, specs.length);
  const root = specs.find((s) => s.id === MENU.ROOT)!;
  assert.equal(root.title, '[extName]');
  assert.equal(root.parentId, undefined);
  // Parents come first and cover every context of their children.
  for (const [i, s] of specs.entries()) {
    if (!s.parentId) continue;
    const pi = specs.findIndex((p) => p.id === s.parentId);
    assert.ok(pi >= 0 && pi < i, s.id);
    for (const c of s.contexts) assert.ok(specs[pi].contexts.includes(c), `${s.id} ${c}`);
  }
  const by = Object.fromEntries(specs.map((s) => [s.id, s]));
  assert.deepEqual(by[MENU.EXPLAIN].contexts, ['link', 'image', 'video', 'audio', 'frame']);
  assert.deepEqual(by[MENU.TEST].contexts, ['selection']);
  assert.deepEqual(by[MENU.BLAME].contexts, ['selection']);
  assert.deepEqual(by[MENU.BISECT].contexts, ['page']);
  assert.deepEqual(by[MENU.LAB], { id: MENU.LAB, title: '[nerdMenuOpenLab]', contexts: ['action'] });
  assert.equal(root.contexts.includes('action'), false);
});

test('explain: link, then image, then frame URL; site is the tab host', () => {
  const tab = { id: 4, url: 'https://www.news.example.ch/article?x=1' };
  const link = labHash({ menuItemId: MENU.EXPLAIN, linkUrl: 'https://ads.example.net/c?a=1&b=2#f', srcUrl: 'https://img.example/x.png', mediaType: 'image' }, tab)!;
  assert.ok(link.startsWith('#lab?'));
  assert.deepEqual(params(link), { url: 'https://ads.example.net/c?a=1&b=2#f', site: 'www.news.example.ch', type: 'main_frame' });
  const img = labHash({ menuItemId: MENU.EXPLAIN, srcUrl: 'https://img.example/x.png', mediaType: 'image' }, tab)!;
  assert.deepEqual(params(img), { url: 'https://img.example/x.png', site: 'www.news.example.ch', type: 'image' });
  const vid = labHash({ menuItemId: MENU.EXPLAIN, srcUrl: 'https://v.example/a.mp4', mediaType: 'video' }, tab)!;
  assert.equal(params(vid).type, 'media');
  const frame = labHash({ menuItemId: MENU.EXPLAIN, frameUrl: 'https://frame.example/f.html', pageUrl: 'https://p.example/' }, undefined)!;
  assert.deepEqual(params(frame), { url: 'https://frame.example/f.html', site: 'p.example', type: 'sub_frame' });
});

test('explain: non-web URLs and pages without a web host', () => {
  assert.equal(labHash({ menuItemId: MENU.EXPLAIN, linkUrl: 'javascript:alert(1)' }, undefined), null);
  assert.equal(labHash({ menuItemId: MENU.EXPLAIN, srcUrl: 'data:image/png;base64,AAAA', mediaType: 'image' }, undefined), null);
  assert.equal(labHash({ menuItemId: MENU.EXPLAIN }, undefined), null);
  const h = labHash({ menuItemId: MENU.EXPLAIN, linkUrl: 'https://a.example/' }, { url: 'chrome://newtab/' })!;
  assert.deepEqual(params(h), { url: 'https://a.example/', type: 'main_frame' });
});

test('selection: test and blame deep links, trimmed and bounded', () => {
  const t = labHash({ menuItemId: MENU.TEST, selectionText: '  ||ads.example^$script,3p  ' }, undefined)!;
  assert.ok(t.startsWith('#lab?filter='));
  assert.equal(params(t).filter, '||ads.example^$script,3p');
  const b = labHash({ menuItemId: MENU.BLAME, selectionText: 'example.com##.ad & more' }, undefined)!;
  assert.ok(b.startsWith('#lab/blame?filter='));
  assert.equal(params(b).filter, 'example.com##.ad & more');
  assert.equal(params(labHash({ menuItemId: MENU.TEST, selectionText: 'x'.repeat(MAX_SELECTION + 50) }, undefined)!).filter.length, MAX_SELECTION);
  assert.equal(labHash({ menuItemId: MENU.TEST, selectionText: '   ' }, undefined), null);
  assert.equal(labHash({ menuItemId: MENU.LAB }, undefined), '#lab');
  assert.equal(labHash({ menuItemId: 'other' }, undefined), null);
});

function fake(on = true) {
  const items = new Map<string, MenuSpec>();
  const log: string[] = [];
  const opened: { url: string; tab: unknown }[] = [];
  const bisects: MsgNerdBisect[] = [];
  let popups = 0;
  const state = { on };
  const deps: NerdMenuDeps = {
    menus: {
      removeAll: async () => {
        log.push('removeAll');
        items.clear();
      },
      create: async (spec) => {
        if (items.has(spec.id)) throw new Error(`duplicate id ${spec.id}`);
        if (spec.parentId && !items.has(spec.parentId)) throw new Error(`missing parent ${spec.parentId}`);
        log.push(`create ${spec.id}`);
        items.set(spec.id, spec);
      },
    },
    msg,
    dashboardUrl: DASH,
    nerdOn: () => state.on,
    openTab: async (url, tab) => {
      opened.push({ url, tab });
    },
    bisect: async (m) => {
      bisects.push(m);
      return { bisect: null };
    },
    openPopup: async () => {
      popups++;
    },
  };
  return { deps, items, log, opened, bisects, state, popups: () => popups };
}

test('sync creates the menus while on, removes them when off, and is a no-op otherwise', async () => {
  const f = fake();
  const m = new NerdMenus(f.deps);
  await m.sync(false); // fresh worker: clean slate even when off
  assert.deepEqual(f.log, ['removeAll']);
  await m.sync(false);
  assert.deepEqual(f.log, ['removeAll']);
  await m.sync(true);
  assert.equal(f.items.size, menuSpecs(msg).length);
  const n = f.log.length;
  await m.sync(true);
  assert.equal(f.log.length, n, 'no rebuild without a change');
  await m.sync(true, true); // install / startup
  assert.equal(f.items.size, menuSpecs(msg).length, 'forced rebuild does not hit duplicate ids');
  await m.sync(false);
  assert.equal(f.items.size, 0);
});

test('a failed create is retried on the next sync', async () => {
  const f = fake();
  let fail = true;
  const create = f.deps.menus.create;
  f.deps.menus.create = async (s) => {
    if (fail) throw new Error('boom');
    return create(s);
  };
  const m = new NerdMenus(f.deps);
  await m.sync(true);
  fail = false;
  await m.sync(true);
  assert.equal(f.items.size, menuSpecs(msg).length);
});

test('clicks open the Lab next to the tab, start the bisect, and do nothing while off', async () => {
  const f = fake();
  const m = new NerdMenus(f.deps);
  const tab = { id: 7, index: 2, windowId: 1, url: 'https://shop.example/' };
  await m.onClicked({ menuItemId: MENU.EXPLAIN, linkUrl: 'https://t.example/p.gif' }, tab);
  assert.equal(f.opened.length, 1);
  assert.ok(f.opened[0].url.startsWith(`${DASH}#lab?url=https%3A%2F%2Ft.example%2Fp.gif&site=shop.example`));
  assert.equal(f.opened[0].tab, tab);
  await m.onClicked({ menuItemId: MENU.LAB }, undefined);
  assert.equal(f.opened[1].url, `${DASH}#lab`);
  await m.onClicked({ menuItemId: MENU.BISECT, pageUrl: tab.url }, tab);
  assert.deepEqual(f.bisects, [{ type: 'nerd:bisect', action: 'start', tabId: 7 }]);
  assert.equal(f.popups(), 1);
  await m.onClicked({ menuItemId: MENU.BISECT }, undefined);
  assert.equal(f.bisects.length, 1, 'no tab, no bisect');
  f.state.on = false;
  await m.onClicked({ menuItemId: MENU.LAB }, undefined);
  assert.equal(f.opened.length, 2);
});
