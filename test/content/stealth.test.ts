// Unit tests for src/main/stealth.ts (native-looking patching). Runs in its
// own node:test process, so patching Function.prototype.toString here does
// not leak into other test files.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createStealth, findAncestorMask, ownStackNeedle, realmAlreadyPatched } from '../../src/main/stealth.ts';

// Frames of the stealth module itself are what must disappear from stacks.
const NEEDLE = 'src/main/stealth.ts';

// Native targets from V8, so toString output is genuinely "[native code]".
const proto = Map.prototype as unknown as Record<string, unknown>;
const nativeGet = Map.prototype.get;
const nativeHas = Map.prototype.has;
const sizeGetter = Object.getOwnPropertyDescriptor(Map.prototype, 'size')!.get!;
const nativeToString = Function.prototype.toString;
const strOf = (f: unknown): string => Reflect.apply(nativeToString, f, []) as string;

const st = createStealth(NEEDLE, 'secret-sentinel', 'secret-reply');

test('wrapMethod keeps native metadata and calls through', () => {
  assert.equal(st.wrapMethod(proto, 'get', (orig) => (t, args) => {
    const v = Reflect.apply(orig, t, args);
    return typeof v === 'number' ? v + 1 : v;
  }), true);
  const m = new Map([['a', 1]]);
  assert.equal(m.get('a'), 2);
  const patched = Map.prototype.get;
  assert.notEqual(patched, nativeGet);
  assert.equal(patched.name, 'get');
  assert.equal(patched.length, 1);
  assert.equal(Object.prototype.hasOwnProperty.call(patched, 'prototype'), false);
  assert.deepEqual(Reflect.ownKeys(patched), Reflect.ownKeys(nativeGet));
  assert.throws(() => new (patched as unknown as new () => unknown)(), TypeError);
  const d = Object.getOwnPropertyDescriptor(Map.prototype, 'get')!;
  assert.equal(d.writable, true);
  assert.equal(d.enumerable, false);
  assert.equal(d.configurable, true);
});

test('missing properties are reported, not created', () => {
  assert.equal(st.wrapMethod(proto, 'noSuchMethod', () => () => 1), false);
  assert.equal(st.wrapMethod(undefined, 'get', () => () => 1), false);
  assert.equal(st.wrapGetter(proto, 'get', () => () => 1), false, 'a method is not a getter');
  assert.equal('noSuchMethod' in Map.prototype, false);
});

test('wrapGetter replaces only the getter', () => {
  assert.equal(st.wrapGetter(proto, 'size', (orig) => (t) => (Reflect.apply(orig, t, []) as number) * 10), true);
  assert.equal(new Map([[1, 1]]).size, 10);
  const d = Object.getOwnPropertyDescriptor(Map.prototype, 'size')!;
  assert.equal(d.set, undefined);
  assert.equal(d.get!.name, 'get size');
});

test('defineGetter creates a native-looking accessor that validates via impl', () => {
  const holder = {} as Record<string, unknown>;
  assert.equal(st.defineGetter(holder, 'globalPrivacyControl', (t) => {
    if (t !== holder) throw new TypeError('Illegal invocation');
    return true;
  }, true), true);
  assert.equal(holder.globalPrivacyControl, true);
  const d = Object.getOwnPropertyDescriptor(holder, 'globalPrivacyControl')!;
  assert.equal(d.enumerable, true);
  assert.equal(d.get!.name, 'get globalPrivacyControl');
  assert.equal(d.get!.length, 0);
  assert.throws(() => d.get!.call({}), /Illegal invocation/);
});

test('installToString masks every proxy and itself', () => {
  st.installToString();
  st.installToString(); // idempotent
  const ts = Function.prototype.toString;
  assert.notEqual(ts, nativeToString);
  assert.equal(ts.call(Map.prototype.get), strOf(nativeGet));
  assert.equal(ts.call(Map.prototype.get), 'function get() { [native code] }');
  assert.equal(String(Map.prototype.get), 'function get() { [native code] }');
  assert.equal(ts.call(Object.getOwnPropertyDescriptor(Map.prototype, 'size')!.get), strOf(sizeGetter));
  assert.equal(ts.call(ts), 'function toString() { [native code] }');
  assert.equal(ts.call(Function.prototype.toString), 'function toString() { [native code] }');
  const gpc = Object.getOwnPropertyDescriptor({} as object, 'x');
  assert.equal(gpc, undefined);
  const holder = {} as Record<string, unknown>;
  st.defineGetter(holder, 'demo', () => 1, false);
  assert.equal(ts.call(Object.getOwnPropertyDescriptor(holder, 'demo')!.get), 'function get demo() { [native code] }');
  // Unrelated functions are untouched.
  function plain(a: number): number {
    return a;
  }
  assert.equal(ts.call(plain), strOf(plain));
  assert.equal(ts.call(nativeHas), 'function has() { [native code] }');
  // Wrong receivers still throw the native TypeError.
  assert.throws(() => ts.call({}), TypeError);
});

test('setPrototypeOf cycle checks behave like natives', () => {
  const f = Map.prototype.get as unknown as object;
  const before = Object.getPrototypeOf(f);
  assert.throws(() => Object.setPrototypeOf(f, f), /Cyclic __proto__ value/);
  assert.throws(() => Object.setPrototypeOf(f, Object.create(f)), /Cyclic __proto__ value/);
  assert.equal(Object.getPrototypeOf(f), before);
  // Non-cyclic changes still work and can be undone.
  const p = Object.create(Function.prototype);
  Object.setPrototypeOf(f, p);
  assert.equal(Object.getPrototypeOf(f), p);
  Object.setPrototypeOf(f, before);
  assert.equal(Object.getPrototypeOf(f), before);
});

/** Node installs Error.prepareStackTrace by default; Chrome pages do not. Emulate Chrome. */
function withoutPrepareStackTrace<T>(fn: () => T): T {
  const E = Error as unknown as { prepareStackTrace?: unknown };
  const desc = Object.getOwnPropertyDescriptor(Error, 'prepareStackTrace');
  delete E.prepareStackTrace;
  try {
    return fn();
  } finally {
    if (desc !== undefined) Object.defineProperty(Error, 'prepareStackTrace', desc);
  }
}

test('errors from patched functions carry no stealth frames', () => {
  let err: unknown;
  withoutPrepareStackTrace(() => {
    try {
      Map.prototype.get.call({} as Map<unknown, unknown>, 'x');
    } catch (e) {
      err = e;
    }
  });
  assert.ok(err instanceof TypeError);
  const stack = String((err as Error).stack);
  assert.ok(/incompatible receiver|called on/.test(stack), stack);
  assert.equal(stack.includes(NEEDLE), false, stack);
  assert.equal(stack.includes('stealth.test.ts'), true, 'caller frames are kept');

  // The emulated "Cyclic __proto__ value" error is cleaned as well.
  withoutPrepareStackTrace(() => {
    assert.throws(
      () => Object.setPrototypeOf(Map.prototype.get, Map.prototype.get),
      (e: unknown) => e instanceof TypeError && /Cyclic/.test(e.message) && !String(e.stack).includes(NEEDLE),
    );
  });
});

test('cleanError leaves stacks alone when the page installed prepareStackTrace', () => {
  const E = Error as unknown as { prepareStackTrace?: unknown };
  const had = Object.prototype.hasOwnProperty.call(Error, 'prepareStackTrace');
  const prev = E.prepareStackTrace;
  E.prepareStackTrace = (_e: unknown, frames: unknown[]) => `frames:${frames.length}`;
  try {
    const e = new Error('x');
    const out = st.cleanError(e);
    assert.equal(out, e);
  } finally {
    if (had) E.prepareStackTrace = prev;
    else delete E.prepareStackTrace;
  }
  assert.equal(st.cleanError(42), 42);
  assert.equal(st.cleanError(null), null);
});

test('the sentinel identifies an already patched realm', () => {
  assert.equal(realmAlreadyPatched('secret-sentinel', 'secret-reply'), true);
  assert.equal(realmAlreadyPatched('wrong', 'secret-reply'), false);
  assert.equal(realmAlreadyPatched('secret-sentinel', 'other'), false);
  // Other primitives still hit the native TypeError.
  assert.throws(() => Function.prototype.toString.call('not-the-sentinel'), TypeError);
});

test('findAncestorMask finds the nearest patched same-origin ancestor', () => {
  const mask = function (this: unknown): string {
    return this === 'secret-sentinel' ? 'secret-reply' : 'x';
  };
  const plain = function (): string {
    return 'nope';
  };
  const realm = (ts: unknown) => ({ Function: { prototype: { toString: ts } } });
  const top: Record<string, unknown> = realm(mask);
  top.parent = top;
  const mid: Record<string, unknown> = realm(plain);
  mid.parent = top;
  const child = { parent: mid } as unknown as Window;
  assert.equal(findAncestorMask(child, 'secret-sentinel', 'secret-reply'), mask);
  assert.equal(findAncestorMask(child, 'other', 'secret-reply'), null);
  const lonely = {} as Record<string, unknown>;
  lonely.parent = lonely;
  assert.equal(findAncestorMask(lonely as unknown as Window, 'secret-sentinel', 'secret-reply'), null);
  // Cross-origin parents throw on access: no delegate, no exception.
  const xo = { get parent(): Window { throw new Error('SecurityError'); } } as unknown as Window;
  assert.equal(findAncestorMask(xo, 'secret-sentinel', 'secret-reply'), null);
});

// Delegation itself needs two realms; it is exercised in Chromium by the
// "iframe.crossRealmToString" probe of test/fixtures/fingerprint.html.
test('a second instance never replaces an installed mask', async () => {
  const calls: unknown[] = [];
  const delegate = function (this: unknown): string {
    calls.push(this);
    return 'delegated';
  };
  const { createStealth: create } = await import('../../src/main/stealth.ts');
  const child = create(NEEDLE);
  // installToString is a no-op when toString is already patched (it is, by `st` above),
  // so check the delegate contract through the already-installed mask instead:
  child.installToString(delegate);
  assert.equal(Function.prototype.toString.call(Map.prototype.get), 'function get() { [native code] }');
  assert.equal(calls.length, 0, 'patched realm did not replace the existing mask');
});

test('ownStackNeedle falls back to the extension scheme outside extensions', () => {
  assert.equal(ownStackNeedle(), 'chrome-extension://');
});
