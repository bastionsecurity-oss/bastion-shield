// Tests for tools/lib/notice-transform.ts: uBO's prevent-clipboard-write
// scriptlet (the vendored file, unchanged) is rewritten so that a blocked
// write dispatches the Bastion notice event instead of drawing uBO's beige
// bar, while the blocking itself stays as in uBO. Fails loudly when the
// vendored scriptlet no longer matches the transform anchors (a vendor update
// must not silently bring the beige bar back).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import vm from 'node:vm';
import type { ScriptletFilter } from '../../src/compiler/types.ts';
import { loadResources, type ResourceSet } from '../../tools/resources.ts';
import { emitScriptlets } from '../../tools/scriptlets.ts';
import { createLogger } from '../../tools/lib/util.ts';
import {
  CLIPBOARD_SCRIPTLET,
  NOTICE_DETAIL_UBO,
  NoticeTransformError,
  noticeEventName,
  transformClipboardScriptlet,
} from '../../tools/lib/notice-transform.ts';

const EVENT = 'bsntest0123456789abcdef01';
let resources: ResourceSet;
let original: string;

before(async () => {
  resources = await loadResources(createLogger('test', true));
  const lib = resources.scriptlets.get(CLIPBOARD_SCRIPTLET);
  assert.ok(lib, `${CLIPBOARD_SCRIPTLET} is in the vendored uBO library`);
  original = lib.code;
});

test('the vendored scriptlet matches the transform anchors', () => {
  const out = transformClipboardScriptlet(original, EVENT);
  assert.ok(original.includes('beige'), 'sanity: the original draws the beige bar');
  assert.ok(!out.includes('beige'));
  assert.ok(!out.includes('DOMParser'));
  assert.ok(out.includes(`'${EVENT}'`));
  assert.ok(out.includes('bastionNotice(text)'));
  new vm.Script(`(${out})`); // still parses
});

test('event names are random, lower-case alphanumeric, and validated', () => {
  const a = noticeEventName();
  const b = noticeEventName();
  assert.match(a, /^bsn[0-9a-f]{24}$/);
  assert.notEqual(a, b);
  assert.throws(() => transformClipboardScriptlet(original, 'x'), NoticeTransformError);
  assert.throws(() => transformClipboardScriptlet(original, "bad'name0123456789abc"), NoticeTransformError);
});

test('a changed upstream scriptlet fails loudly instead of keeping the beige bar', () => {
  const variants = [
    original.replace('const htmlTemplate = [', 'const template = ['),
    original.replace('let currentAlert = null;', 'let alertNode = null;'),
    original.replace(/domAlert\(\s*text\s*\);/, 'showAlert(text);'),
    original.replace('function preventClipboardWrite(', 'function preventClipboardWrite2('),
    original + '\n// const htmlTemplate = [',
  ];
  for (const v of variants) assert.throws(() => transformClipboardScriptlet(v, EVENT), NoticeTransformError);
});

interface Run {
  events: { type: string; detail: unknown }[];
  /** Result of a trapped call: 'blocked' or 'native'. */
  writeText(text: string): string;
  execCopy(selection: string): string;
}

/**
 * Evaluate the transformed scriptlet with small stand-ins for uBO's helpers
 * (safeSelf, proxyApplyFn, runAt) and the frame, then fire the mousemove
 * that installs the traps.
 */
function run(code: string, args: string[]): Run {
  const events: Run['events'] = [];
  const traps = new Map<string, (ctx: { callArgs: unknown[]; reflect(): unknown }) => unknown>();
  let mousemove: (() => void) | undefined;
  let selection = '';
  const sandbox: Record<string, unknown> = {};
  const ctx = vm.createContext(sandbox);
  vm.runInContext('globalThis.self = globalThis;', ctx);
  class EventTargetStub {
    dispatchEvent(ev: { type: string; detail: unknown }): boolean {
      events.push({ type: ev.type, detail: ev.detail });
      return true;
    }
  }
  sandbox.EventTarget = EventTargetStub;
  sandbox.CustomEvent = class {
    type: string;
    detail: unknown;
    constructor(type: string, init: { detail?: unknown }) {
      this.type = type;
      this.detail = init.detail;
    }
  };
  sandbox.document = {
    addEventListener(type: string, fn: () => void) {
      if (type === 'mousemove') mousemove = fn;
    },
    getSelection: () => ({ toString: () => selection }),
  };
  sandbox.safeSelf = () => ({
    makeLogPrefix: () => '',
    initPattern: (p: string) => {
      const m = /^\/(.+)\/([a-z]*)$/s.exec(p);
      return { re: m ? new RegExp(m[1], m[2]) : new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) };
    },
    parseVarargs: (a: string[]) => {
      const o: Record<string, string> = {};
      for (let i = 0; i + 1 < a.length; i += 2) o[a[i]] = a[i + 1];
      return o;
    },
    testPattern: (p: { re: RegExp }, t: string) => p.re.test(t),
    uboLog() {},
  });
  sandbox.proxyApplyFn = (path: string, fn: (ctx: { callArgs: unknown[]; reflect(): unknown }) => unknown) => traps.set(path, fn);
  sandbox.runAt = (fn: () => void) => fn();
  vm.runInContext(`(${code}).apply(null, ${JSON.stringify(args)});`, ctx);
  assert.ok(mousemove, 'traps wait for the first mousemove');
  mousemove();
  const call = (path: string, callArgs: unknown[]): string => {
    let native = false;
    void traps.get(path)!({ callArgs, reflect: () => (native = true) });
    return native ? 'native' : 'blocked';
  };
  return {
    events,
    writeText: (text) => call('navigator.clipboard.writeText', [text]),
    execCopy: (sel) => {
      selection = sel;
      return call('document.execCommand', ['copy']);
    },
  };
}

test('blocked writes dispatch the notice event; uBO blocking is unchanged', () => {
  const out = transformClipboardScriptlet(original, EVENT);
  const r = run(out, ['/^danger /', 'domAlert', 'uBO says ${text}', 'excludeMatches', '/^danger ok/']);
  assert.equal(r.writeText('danger now'), 'blocked');
  assert.equal(r.writeText('harmless'), 'native');
  assert.equal(r.writeText('danger ok'), 'native', 'excludeMatches still applies');
  assert.equal(r.execCopy('  danger copy  '), 'blocked');
  assert.equal(r.execCopy('fine'), 'native');
  assert.deepEqual(r.events, [
    { type: EVENT, detail: `${NOTICE_DETAIL_UBO}danger now` },
    { type: EVENT, detail: `${NOTICE_DETAIL_UBO}danger copy` }, // uBO trims
  ]);
});

test('without domAlert the scriptlet blocks silently, as in uBO', () => {
  const r = run(transformClipboardScriptlet(original, EVENT), ['/^danger /']);
  assert.equal(r.writeText('danger now'), 'blocked');
  assert.deepEqual(r.events, []);
});

test('emitScriptlets routes the generic ClickFix filter to the notice', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bastion-notice-'));
  try {
    const f: ScriptletFilter = {
      name: CLIPBOARD_SCRIPTLET,
      world: 'MAIN',
      args: ['/^danger /msi', 'domAlert', 'Beware: ${text}', 'excludeMatches', '/^git /i'],
      hosts: [],
      excludedHosts: ['example.edu'],
      exception: false,
      raw: '*,~example.edu##+js(prevent-clipboard-write, …)',
    };
    const r = await emitScriptlets({ outDir: dir, resources, log: createLogger('test', true), lists: [{ listId: 'ublock', trusted: true, scriptlets: [f] }] });
    assert.match(r.noticeEvent, /^bsn[0-9a-f]{24}$/);
    const core = await readFile(join(dir, 'scriptlets', 'scriptlet-core-main.js'), 'utf8');
    assert.ok(core.includes(r.noticeEvent));
    assert.ok(!core.includes('beige'));
    const fixed = await emitScriptlets({
      outDir: join(dir, 'b'),
      resources,
      log: createLogger('test', true),
      noticeEvent: EVENT,
      lists: [{ listId: 'ublock', trusted: true, scriptlets: [f] }],
    });
    assert.equal(fixed.noticeEvent, EVENT);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
