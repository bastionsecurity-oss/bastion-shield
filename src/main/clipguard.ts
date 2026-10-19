// Bastion Shield — nerd mode clipboard guard, MAIN world (dist/main/clipguard.js).
//
// ClickFix protection: pages that put a command on the clipboard and ask the
// user to paste it into Win+R / Terminal. Registered by the service worker
// with nerd-relay.js (ISOLATED) when nerd mode and the clipboard guard are
// on: <all_urls>, document_start, all frames, matchOriginAsFallback, not on
// sites with protection off (registrations.ts).
//
// Hooks (all via stealth.ts, so they keep native name/length/toString):
//   Clipboard.prototype.writeText(text)
//   Clipboard.prototype.write(items)     text/plain of ClipboardItems; the
//                                        check runs when the data resolves
//   DataTransfer.prototype.setData       only on the clipboardData of a
//                                        copy/cut event
//   Document.prototype.execCommand       'copy' / 'cut': the copied selection
//                                        is checked in our copy listener
// Each payload goes to the relay through a synchronous, cancelable event
// (nerd-channel.ts); the relay runs the detector and the allow/deny rule
// (clip-detect.ts: decideClip) with the isolated world's pristine built-ins
// and cancels the event to block. A blocked payload is replaced by
// CLIP_REPLACEMENT (a harmless shell comment); the relay notifies the
// service worker and shows a toast. Without the relay (failed injection)
// every check answers "allow".
//
// Never throws into the page: if anything goes wrong the original call runs
// with the original arguments. Known gaps (as for privacy.js): workers,
// and same-origin about:blank iframes used in the same task they were
// created in (their prototypes are unpatched until our scripts run there).
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { CLIP_REPLACEMENT } from './clip-replacement.ts';
import { encodeClipCheck } from './nerd-channel.ts';
import type { ClipSource } from './nerd-channel.ts';
import { setupNerdMain } from './nerd-main.ts';
import type { NerdMain } from './nerd-main.ts';

const RApply = Reflect.apply;
const ObjGetDesc = Object.getOwnPropertyDescriptor;
const ObjGetProto = Object.getPrototypeOf;
const ObjCreate = Object.create;
const ObjDefine = Object.defineProperty;
const ArrayIsArray = Array.isArray;
const StringCtor = String;
const strToLower = String.prototype.toLowerCase;
const promiseThen = Promise.prototype.then;
const WeakSetCtor = WeakSet;
const wsAdd = WeakSet.prototype.add;
const wsHas = WeakSet.prototype.has;
const G = globalThis as unknown as Record<string, unknown>;

type AnyFn = (...args: unknown[]) => unknown;

/** Payloads shorter than this are never commands worth a round trip. */
const MIN_CHECK_LENGTH = 6;

/** arr[i] = v without running setters a page may have put on Array.prototype. */
function setIndex(arr: unknown[], i: number, v: unknown): void {
  const d = ObjCreate(null) as PropertyDescriptor;
  d.value = v;
  d.writable = true;
  d.enumerable = true;
  d.configurable = true;
  ObjDefine(arr, i, d);
}

/** [first, ...rest of args] built with setIndex. */
function withFirst(first: unknown, args: unknown[]): unknown[] {
  const a: unknown[] = [first];
  for (let i = 1; i < args.length; i++) setIndex(a, i, args[i]);
  return a;
}

function protoOf(name: string): Record<string, unknown> | undefined {
  try {
    const c = G[name] as { prototype?: unknown } | undefined;
    const p = typeof c === 'function' ? c.prototype : undefined;
    return p !== null && typeof p === 'object' ? (p as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

function method(proto: unknown, name: string): AnyFn | undefined {
  try {
    if (proto === null || proto === undefined) return undefined;
    const f = ObjGetDesc(proto, name)?.value;
    return typeof f === 'function' ? (f as AnyFn) : undefined;
  } catch {
    return undefined;
  }
}

function getter(proto: unknown, name: string): AnyFn | undefined {
  try {
    if (proto === null || proto === undefined) return undefined;
    const f = ObjGetDesc(proto, name)?.get;
    return typeof f === 'function' ? (f as AnyFn) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * ToString as WebIDL would do it, once, so the native call receives the
 * very string we checked. Symbols and throwing objects return undefined:
 * the caller then passes the original value and lets the native report it.
 */
function toStr(v: unknown): string | undefined {
  if (typeof v === 'string') return v;
  if (typeof v === 'symbol') return undefined;
  try {
    return StringCtor(v);
  } catch {
    return undefined;
  }
}

function install(nm: NerdMain): void {
  const st = nm.stealth;
  const ask = (source: ClipSource, userCopy: boolean, text: string): boolean => {
    if (source !== 'exec' && text.length < MIN_CHECK_LENGTH) return false;
    return nm.send(encodeClipCheck(source, userCopy, text));
  };

  // Script-triggered copy in progress (execCommand nesting depth).
  let execDepth = 0;
  // clipboardData objects of copy/cut events (setData elsewhere, e.g. drag and drop, is not ours).
  const clipboardDatas = new WeakSetCtor<object>();

  const DTP = protoOf('DataTransfer');
  const nativeSetData = method(DTP, 'setData');
  const clipboardDataGet = getter(protoOf('ClipboardEvent'), 'clipboardData');
  const preventDefault = method(protoOf('Event'), 'preventDefault');
  const addListener = method(protoOf('EventTarget'), 'addEventListener');

  // 1. Copy/cut listener: registered now (document_start), so it is the
  //    first capture listener on window and sees every copy before page code.
  if (clipboardDataGet !== undefined && addListener !== undefined) {
    const onCopy = (ev: Event): void => {
      try {
        const cd = RApply(clipboardDataGet, ev, []) as object | null;
        if (cd === null || typeof cd !== 'object') return;
        RApply(wsAdd, clipboardDatas, [cd]);
        // execCommand('copy') copies the selection: the relay reads it itself.
        if (execDepth > 0 && nativeSetData !== undefined && preventDefault !== undefined && ask('exec', false, '')) {
          RApply(nativeSetData, cd, ['text/plain', CLIP_REPLACEMENT]);
          RApply(preventDefault, ev, []);
        }
      } catch {
        // never disturb the copy
      }
    };
    const opts = ObjCreate(null) as AddEventListenerOptions;
    opts.capture = true;
    RApply(addListener, window, ['copy', onCopy, opts]);
    RApply(addListener, window, ['cut', onCopy, opts]);
  }

  // 2. DataTransfer.setData inside a copy/cut handler.
  st.wrapMethod(DTP, 'setData', (orig) => (t, args) => {
    let a = args;
    try {
      if (t !== null && typeof t === 'object' && RApply(wsHas, clipboardDatas, [t]) && args.length >= 2) {
        const format = toStr(args[0]);
        const data = toStr(args[1]);
        if (format !== undefined && data !== undefined) {
          a = [format, data];
          const f = RApply(strToLower, format, []) as string;
          if ((f === 'text/plain' || f === 'text' || f === 'text/unicode') && ask('setData', execDepth === 0, data)) {
            a = [format, CLIP_REPLACEMENT];
          }
        }
      }
    } catch {
      a = args;
    }
    return RApply(orig, t, a);
  });

  // 3. execCommand('copy' | 'cut'): mark the nested copy event as script-triggered.
  st.wrapMethod(protoOf('Document'), 'execCommand', (orig) => (t, args) => {
    let a = args;
    let copy = false;
    try {
      const cmd = args.length > 0 ? toStr(args[0]) : undefined;
      if (cmd !== undefined) {
        a = withFirst(cmd, args);
        const c = RApply(strToLower, cmd, []) as string;
        copy = c === 'copy' || c === 'cut';
      }
    } catch {
      a = args;
      copy = false;
    }
    if (!copy) return RApply(orig, t, a);
    execDepth++;
    try {
      return RApply(orig, t, a);
    } finally {
      execDepth--;
    }
  });

  const CP = protoOf('Clipboard');

  // 4. navigator.clipboard.writeText
  st.wrapMethod(CP, 'writeText', (orig) => (t, args) => {
    let a = args;
    try {
      if (args.length > 0) {
        const text = toStr(args[0]);
        if (text !== undefined) {
          a = [text];
          if (ask('writeText', false, text)) a = [CLIP_REPLACEMENT];
        }
      }
    } catch {
      a = args;
    }
    return RApply(orig, t, a);
  });

  // 5. navigator.clipboard.write: rebuild ClipboardItems whose text/plain
  //    data is checked once it resolves. The replacement blobs are made now,
  //    before page code can tamper with Array iteration or Blob.
  const CIP = protoOf('ClipboardItem');
  const CICtor = G.ClipboardItem as (new (items: Record<string, unknown>, opts?: object) => object) | undefined;
  const BlobCtor = G.Blob as (new (parts: unknown[], opts?: object) => object) | undefined;
  const typesGet = getter(CIP, 'types');
  const styleGet = getter(CIP, 'presentationStyle');
  const getType = method(CIP, 'getType');
  const blobText = method(protoOf('Blob'), 'text');
  let plainBlob: object | undefined;
  let htmlBlob: object | undefined;
  try {
    if (BlobCtor !== undefined) {
      const po = ObjCreate(null) as Record<string, string>;
      po.type = 'text/plain';
      plainBlob = new BlobCtor([CLIP_REPLACEMENT], po);
      const ho = ObjCreate(null) as Record<string, string>;
      ho.type = 'text/html';
      htmlBlob = new BlobCtor(['<pre>' + CLIP_REPLACEMENT + '</pre>'], ho);
    }
  } catch {
    plainBlob = undefined;
  }

  if (CIP !== undefined && CICtor !== undefined && typesGet !== undefined && getType !== undefined && blobText !== undefined && plainBlob !== undefined) {
    const guardItem = (item: unknown): unknown => {
      if (item === null || typeof item !== 'object' || ObjGetProto(item) !== CIP) return item;
      const types = RApply(typesGet, item, []) as readonly string[];
      if (!ArrayIsArray(types)) return item;
      let hasPlain = false;
      for (let i = 0; i < types.length; i++) if (types[i] === 'text/plain') hasPlain = true;
      if (!hasPlain) return item;
      const plainP = RApply(getType, item, ['text/plain']) as Promise<unknown>;
      // Resolves to true when the plain text must be replaced.
      const blockP = RApply(promiseThen, plainP, [
        (blob: unknown) =>
          RApply(promiseThen, RApply(blobText, blob, []) as Promise<unknown>, [
            (txt: unknown) => typeof txt === 'string' && ask('write', false, txt),
          ]),
        () => false,
      ]) as Promise<boolean>;
      const record = ObjCreate(null) as Record<string, unknown>;
      for (let i = 0; i < types.length; i++) {
        const type = types[i];
        record[type] = RApply(promiseThen, blockP, [
          (block: unknown) => {
            if (block === true && type === 'text/plain') return plainBlob;
            if (block === true && type === 'text/html' && htmlBlob !== undefined) return htmlBlob;
            return RApply(getType as AnyFn, item, [type]);
          },
          () => RApply(getType as AnyFn, item, [type]),
        ]);
      }
      const opts = ObjCreate(null) as Record<string, unknown>;
      if (styleGet !== undefined) opts.presentationStyle = RApply(styleGet, item, []);
      return new CICtor(record, opts);
    };
    st.wrapMethod(CP, 'write', (orig) => (t, args) => {
      let a = args;
      try {
        const items = args[0];
        if (ArrayIsArray(items)) {
          const copy: unknown[] = [];
          for (let i = 0; i < items.length; i++) setIndex(copy, i, guardItem(items[i]));
          a = withFirst(copy, args);
        }
      } catch {
        a = args;
      }
      return RApply(orig, t, a);
    });
  }
}

function main(): void {
  const nm = setupNerdMain('clipguard');
  if (nm === null) return;
  try {
    install(nm);
  } catch {
    // whatever was patched stays patched; the rest stays native
  }
  nm.finish();
}

try {
  main();
} catch {
  // never throw into the page
}
