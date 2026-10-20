// Bastion Shield — low-visibility patching of built-in functions for the
// MAIN-world privacy script.
//
// Approach (and why):
//  * Each patched function or getter is replaced by a Proxy whose target is
//    the ORIGINAL native function. A Proxy forwards every property operation
//    to the native target, so `name`, `length`, the absent `prototype`, "not
//    a constructor", own-key lists and `class X extends fn` error messages
//    are exactly the native ones. A hand-written wrapper function gets most
//    of these wrong and leaks its source text in some error messages.
//  * V8 prints a Proxy as "function () { [native code] }" (no name), so
//    Function.prototype.toString is itself replaced by such a Proxy that
//    returns the target's native string for our proxies (and its own native
//    string for itself).
//  * The classic proxy probe `Object.setPrototypeOf(fn, fn)` does not throw
//    for proxies (the spec stops the cycle check at a proxy). Our proxies
//    get a setPrototypeOf trap that performs the check and throws the same
//    "Cyclic __proto__ value" TypeError natives throw.
//  * Errors leaving a trap (e.g. "Illegal invocation" for a bad receiver)
//    carry a stack frame that points into chrome-extension://. That frame is
//    removed from error.stack before rethrowing, unless the page installed
//    Error.prepareStackTrace (reading .stack would run page code from our
//    frame, which is worse).
//
// Remaining, documented limits: Reflect.setPrototypeOf(fn, fn) throws where
// natives return false; Function.prototype.toString taken from ANOTHER realm
// (a same-origin iframe) prints our proxies without a name; stack traces
// captured by page code that runs inside our frames (valueOf callbacks on
// arguments) can still show the extension URL. Workers are not patched.
//
// All built-ins used at call time are captured when this module loads, which
// happens before any page script (document_start, MAIN world).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const RApply = Reflect.apply;
const RSetProto = Reflect.setPrototypeOf;
const ObjDefine = Object.defineProperty;
const ObjGetDesc = Object.getOwnPropertyDescriptor;
const ObjGetProto = Object.getPrototypeOf;
const ObjCreate = Object.create;
const ObjHasOwn = Object.prototype.hasOwnProperty;
const ProxyCtor = Proxy;
const WeakMapCtor = WeakMap;
const wmGet = WeakMap.prototype.get;
const wmSet = WeakMap.prototype.set;
const wmHas = WeakMap.prototype.has;
const ErrorCtor = Error;
const TypeErrorCtor = TypeError;
const strIndexOf = String.prototype.indexOf;
const strSplit = String.prototype.split;
const FnProto = Function.prototype;
const fnToString = Function.prototype.toString;

type AnyFn = (...args: unknown[]) => unknown;

function ownField(o: object, k: string): unknown {
  return RApply(ObjHasOwn, o, [k]) ? (o as Record<string, unknown>)[k] : undefined;
}
/** Implementation of a patched method: receives the receiver and the argument list. */
export type MethodImpl = (thisArg: unknown, args: unknown[]) => unknown;

export interface Stealth {
  /** Replace proto[name] (a method) with a proxy around the original. Returns false if absent. */
  wrapMethod(proto: object | null | undefined, name: string, make: (orig: AnyFn) => MethodImpl): boolean;
  /** Replace the getter of accessor proto[name]. Returns false if absent. */
  wrapGetter(proto: object | null | undefined, name: string, make: (origGet: AnyFn) => (thisArg: unknown) => unknown): boolean;
  /** Define a new accessor proto[name] whose getter prints as native code. */
  defineGetter(proto: object | null | undefined, name: string, impl: (thisArg: unknown) => unknown, enumerable: boolean): boolean;
  /**
   * Install the Function.prototype.toString mask (idempotent). Call once
   * after patching. `delegate` is the mask of an already patched same-origin
   * ancestor realm (see findAncestorMask): functions this realm does not
   * know are printed by it, so a child realm's toString shows the parent's
   * patched functions as native too (the classic "clean iframe" probe).
   */
  installToString(delegate?: AnyFn | null): void;
  /** Exposed for the unit tests and for privacy.ts error paths. */
  cleanError(e: unknown): unknown;
}

/**
 * @param needle Substring identifying our own stack frames (the extension
 *   origin, e.g. "chrome-extension://<id>/").
 * @param sentinel Optional secret receiver: Function.prototype.toString
 *   called with it returns sentinelReply. Lets a second copy of the privacy
 *   script in the same realm detect that the realm is already patched,
 *   without any page-visible marker.
 */
export function createStealth(needle: string, sentinel?: string, sentinelReply?: string): Stealth {
  // proxy -> original function, or a literal native-looking string.
  const masks = new WeakMapCtor<object, AnyFn | string>();
  let toStringInstalled = false;

  const cleanError = (e: unknown): unknown => {
    try {
      if (e === null || typeof e !== 'object' || needle === '') return e;
      if (ObjGetDesc(ErrorCtor, 'prepareStackTrace') !== undefined) return e;
      const d = ObjGetDesc(e, 'stack');
      if (d === undefined) return e;
      // Descriptor objects inherit from the page's Object.prototype: only
      // read own fields so a page-defined Object.prototype.get is never hit.
      const value = ownField(d, 'value');
      const get = ownField(d, 'get');
      const set = ownField(d, 'set');
      let s: unknown;
      if (typeof get === 'function') s = RApply(get, e, []);
      else s = value;
      if (typeof s !== 'string' || RApply(strIndexOf, s, [needle]) === -1) return e;
      const lines = RApply(strSplit, s, ['\n']) as string[];
      let out = '';
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (RApply(strIndexOf, line, [needle]) !== -1) continue;
        out = out === '' ? line : out + '\n' + line;
      }
      if (typeof set === 'function') RApply(set, e, [out]);
      else if (ownField(d, 'writable') === true) {
        // Null-prototype descriptor: ToPropertyDescriptor must not see page-defined Object.prototype.get/set.
        const nd = ObjCreate(null) as PropertyDescriptor;
        nd.value = out;
        nd.writable = true;
        nd.enumerable = false;
        nd.configurable = true;
        ObjDefine(e, 'stack', nd);
      }
    } catch {
      // Best effort only.
    }
    return e;
  };

  const makeProxy = (target: AnyFn, impl: MethodImpl): AnyFn => {
    let self: AnyFn | null = null;
    const handler = ObjCreate(null) as ProxyHandler<AnyFn>;
    handler.apply = (_t: AnyFn, thisArg: unknown, args: unknown[]): unknown => {
      try {
        return impl(thisArg, args);
      } catch (e) {
        throw cleanError(e);
      }
    };
    handler.setPrototypeOf = (t: AnyFn, proto: object | null): boolean => {
      let p: unknown = proto;
      for (let n = 0; n < 100000 && p !== null && (typeof p === 'object' || typeof p === 'function'); n++) {
        if (p === self || p === t) throw cleanError(new TypeErrorCtor('Cyclic __proto__ value'));
        p = ObjGetProto(p as object);
      }
      return RSetProto(t, proto);
    };
    self = new ProxyCtor(target, handler);
    RApply(wmSet, masks, [self, target]);
    return self;
  };

  const isFn = (v: unknown): v is AnyFn => typeof v === 'function';

  return {
    cleanError,

    wrapMethod(proto, name, make) {
      try {
        if (proto === null || proto === undefined) return false;
        const desc = ObjGetDesc(proto, name);
        if (desc === undefined || !isFn(desc.value)) return false;
        const orig = desc.value;
        const proxy = makeProxy(orig, make(orig));
        ObjDefine(proto, name, {
          value: proxy,
          writable: desc.writable,
          enumerable: desc.enumerable,
          configurable: desc.configurable,
        });
        return true;
      } catch {
        return false;
      }
    },

    wrapGetter(proto, name, make) {
      try {
        if (proto === null || proto === undefined) return false;
        const desc = ObjGetDesc(proto, name);
        if (desc === undefined || !isFn(desc.get)) return false;
        const origGet = desc.get as AnyFn;
        const impl = make(origGet);
        const proxy = makeProxy(origGet, (thisArg) => impl(thisArg));
        ObjDefine(proto, name, {
          get: proxy,
          set: desc.set,
          enumerable: desc.enumerable,
          configurable: desc.configurable,
        });
        return true;
      } catch {
        return false;
      }
    },

    defineGetter(proto, name, impl, enumerable) {
      try {
        if (proto === null || proto === undefined) return false;
        const existing = ObjGetDesc(proto, name);
        if (existing !== undefined && existing.configurable === false) return false;
        // The proxy target only provides identity and metadata: a getter
        // from an accessor literal has the native-like name "get <name>",
        // length 0 and no prototype. Calls go to impl.
        const holder = ObjCreate(null) as Record<string, unknown>;
        ObjDefine(holder, name, { get: () => undefined, configurable: true });
        const fn = ObjGetDesc(holder, name)!.get as AnyFn;
        ObjDefine(fn, 'name', { value: `get ${name}`, configurable: true });
        const proxy = makeProxy(fn, (thisArg) => impl(thisArg));
        RApply(wmSet, masks, [proxy, `function get ${name}() { [native code] }`]);
        ObjDefine(proto, name, { get: proxy, set: undefined, enumerable, configurable: true });
        return true;
      } catch {
        return false;
      }
    },

    installToString(delegate) {
      if (toStringInstalled) return;
      toStringInstalled = true;
      try {
        const desc = ObjGetDesc(FnProto, 'toString');
        if (desc === undefined || desc.value !== fnToString) return;
        const proxy = makeProxy(fnToString as AnyFn, (thisArg, args) => {
          if (sentinel !== undefined && thisArg === sentinel) return sentinelReply;
          if (thisArg !== null && (typeof thisArg === 'function' || typeof thisArg === 'object')) {
            if (RApply(wmHas, masks, [thisArg])) {
              const m = RApply(wmGet, masks, [thisArg]) as AnyFn | string;
              return typeof m === 'string' ? m : RApply(fnToString, m, []);
            }
          }
          // Only functions are delegated: errors for bad receivers must come
          // from this realm's TypeError.
          if (typeof thisArg === 'function' && typeof delegate === 'function') {
            try {
              return RApply(delegate, thisArg, []);
            } catch {
              // fall through to the local native
            }
          }
          return RApply(fnToString, thisArg, args);
        });
        ObjDefine(FnProto, 'toString', {
          value: proxy,
          writable: desc.writable,
          enumerable: desc.enumerable,
          configurable: desc.configurable,
        });
      } catch {
        // Leave toString alone if anything is off.
      }
    },
  };
}

/**
 * True when another copy of this script already patched the realm: the
 * installed toString answers the sentinel. Uses the current (possibly
 * patched) Function.prototype.toString; never throws.
 */
export function realmAlreadyPatched(sentinel: string, sentinelReply: string): boolean {
  try {
    const current = ObjGetDesc(FnProto, 'toString');
    if (current === undefined || typeof current.value !== 'function') return false;
    // No "=== fnToString means unpatched" shortcut: a second copy of this
    // script loads after the first one patched the realm and captures the
    // first copy's proxy as fnToString. The native toString throws a
    // TypeError for the string receiver, which reads as "not patched".
    return RApply(current.value, sentinel, []) === sentinelReply;
  } catch {
    return false;
  }
}

/**
 * The toString mask of the nearest same-origin ancestor realm patched by
 * this script with the same key (it answers the sentinel), or null.
 * Cross-origin ancestors end the search (accessing them throws).
 */
export function findAncestorMask(win: Window, sentinel: string, sentinelReply: string): AnyFn | null {
  try {
    let w: Window = win;
    for (let depth = 0; depth < 16; depth++) {
      const parent = w.parent;
      if (parent === null || parent === w) return null;
      const ts = (parent as unknown as { Function: FunctionConstructor }).Function.prototype.toString as unknown as AnyFn;
      if (RApply(ts, sentinel, []) === sentinelReply) return ts;
      w = parent;
    }
  } catch {
    // cross-origin ancestor or exotic window
  }
  return null;
}

/**
 * Our own script origin as it appears in stack traces, read once at start
 * (before page code can install Error.prepareStackTrace). Falls back to the
 * generic extension scheme.
 */
export function ownStackNeedle(): string {
  try {
    const s = new ErrorCtor().stack;
    if (typeof s === 'string') {
      const m = /((?:chrome|moz|safari-web)?-?extension:\/\/[^/\s)]+\/)/.exec(s);
      if (m !== null) return m[1];
    }
  } catch {
    // ignore
  }
  return 'chrome-extension://';
}
