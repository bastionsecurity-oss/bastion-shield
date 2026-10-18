// Bastion Shield — MAIN-world privacy script (dist/main/privacy.js).
//
// Registered by the service worker at document_start in every frame
// (MAIN world, allFrames, matchOriginAsFallback) right after the seed and
// config files (ARCHITECTURE §9):
//   js: [s0-<n>.js, ..., s15-<n>.js, cfg-<level>-gpc<0|1>.js, privacy.js]
// The seed files leave self.__bastionSeeds (SEED_SETS = 16 uint32 words, one
// per file, each picked from a set of SEED_FILES_PER_SET public words: 2^64
// session seeds) and the cfg file self.__bastionCfg = {fp, gpc}. Both are
// read and deleted here before any page script runs.
//
// What it does:
//  * GPC: navigator.globalPrivacyControl === true (the Sec-GPC header is a DNR rule).
//  * Fingerprinting "standard": deterministic, sparse noise on canvas 2D /
//    OffscreenCanvas / WebGL pixel read-back and Web Audio data; reduced
//    navigator.hardwareConcurrency and navigator.deviceMemory.
//  * "strict" adds: generic WebGL UNMASKED_* strings, navigator.languages =
//    [navigator.language], speechSynthesis.getVoices() = [], and
//    enumerateDevices() shuffled without labels.
// Noise is keyed by HMAC-SHA-256(all seed words, top-level site) (farble.ts
// deriveSiteKey), so a site sees stable values for the whole browser session
// while two sites (and a third-party frame on two sites) see unrelated
// values, and no observable lets a page solve the seed one set at a time.
//
// Compatibility guards (maps, office suites, captchas, players, editors):
// noise is ~0.4 % LSB flips on non-transparent pixels, never alpha; blank and
// solid-colour regions, getImageData reads under 16 px (eyedroppers, hit
// tests), readPixels under 64 px (GPU picking) and readPixels from
// framebuffer objects (GPGPU) stay exact; toDataURL/toBlob encode a farbled
// copy so the visible canvas is never touched.
//
// Rules: never throw into the page, never break exotic receivers (the
// original is always called and its errors propagate unchanged), keep
// name/length/toString of patched functions native (see stealth.ts).
// Known gaps: Web Workers / Service Workers / worklets are not patched
// (content scripts cannot run there); a same-origin iframe accessed in the
// same task it was created in may expose unpatched prototypes before this
// script is injected into it; lossy encodings (JPEG/WebP) mostly quantise
// the LSB noise away (as with Brave's farbling); fonts and screen metrics
// are not farbled.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import type { FingerprintLevel } from '../shared/types.ts';
import { SEED_SETS } from '../shared/constants.ts';
import { registrableDomain } from '../shared/hash.ts';
import {
  audioKey,
  deriveSiteKey,
  farbleBytes,
  farbleConcurrency,
  farbleDeviceMemory,
  farbleFloats,
  farblePixels,
  flipThreshold,
  keyedWord,
  lengthOf,
  MAX_AUDIO_SAMPLES,
  MAX_FARBLE_PIXELS,
  MIN_FLIPS,
  normalizeSeeds,
  Prng,
  PURPOSE,
  shuffleInPlace,
} from './farble.ts';
import type { Stealth } from './stealth.ts';
import { createStealth, findAncestorMask, ownStackNeedle, realmAlreadyPatched } from './stealth.ts';

// ---------------------------------------------------------------------------
// 1. Take the delivery globals before anything else.
// ---------------------------------------------------------------------------

const G = globalThis as unknown as Record<string, unknown>;

function takeGlobal(name: string): unknown {
  let v: unknown;
  try {
    v = G[name];
  } catch {
    return undefined;
  }
  try {
    delete G[name];
  } catch {
    // Non-configurable (declared with var): fall through and blank it.
  }
  try {
    if (name in G) G[name] = undefined;
  } catch {
    // ignore
  }
  return v;
}

const rawSeeds = takeGlobal('__bastionSeeds');
const rawCfg = takeGlobal('__bastionCfg');

// ---------------------------------------------------------------------------
// 2. Built-ins used at call time (captured before page scripts run).
// ---------------------------------------------------------------------------

const RApply = Reflect.apply;
const ObjGetDesc = Object.getOwnPropertyDescriptor;
const ObjGetProto = Object.getPrototypeOf;
const ObjCreate = Object.create;
const ObjFreeze = Object.freeze;
const WeakSetCtor = WeakSet;
const wsHas = WeakSet.prototype.has;
const wsAdd = WeakSet.prototype.add;
const I32 = Int32Array;
const mathCeil = Math.ceil;
const arraySlice = Array.prototype.slice;
const arrayIsArray = Array.isArray;
const promiseThen = Promise.prototype.then;
const strIndexOf = String.prototype.indexOf;
const U8Proto = Uint8Array.prototype;
const U8CProto = Uint8ClampedArray.prototype;
const F32Proto = Float32Array.prototype;

type AnyFn = (...args: unknown[]) => unknown;
type Proto = Record<string, unknown> | undefined;

/** Original accessor half (get/set) of proto[name], or undefined. */
function accessor(proto: unknown, name: string, which: 'get' | 'set'): AnyFn | undefined {
  try {
    if (proto === null || proto === undefined) return undefined;
    const d = ObjGetDesc(proto, name);
    const f = d === undefined ? undefined : d[which];
    return typeof f === 'function' ? (f as AnyFn) : undefined;
  } catch {
    return undefined;
  }
}

/** Original method proto[name], or undefined. */
function method(proto: unknown, name: string): AnyFn | undefined {
  try {
    if (proto === null || proto === undefined) return undefined;
    const d = ObjGetDesc(proto, name);
    const f = d === undefined ? undefined : d.value;
    return typeof f === 'function' ? (f as AnyFn) : undefined;
  } catch {
    return undefined;
  }
}

function protoOf(ctorName: string): Proto {
  try {
    const c = G[ctorName] as { prototype?: unknown } | undefined;
    const p = typeof c === 'function' ? c.prototype : undefined;
    return p !== null && typeof p === 'object' ? (p as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

function safe(fn: () => void): void {
  try {
    fn();
  } catch {
    // A feature that cannot be patched stays native.
  }
}

// ---------------------------------------------------------------------------
// 3. Configuration, site and keys.
// ---------------------------------------------------------------------------

interface PrivacyCfg {
  fp: FingerprintLevel;
  gpc: boolean;
}

function parseCfg(raw: unknown): PrivacyCfg {
  // Missing config means a broken registration; fall back to the product defaults.
  const cfg: PrivacyCfg = { fp: 'standard', gpc: true };
  if (raw === null || typeof raw !== 'object') return cfg;
  const r = raw as Record<string, unknown>;
  if (r.fp === 'off' || r.fp === 'standard' || r.fp === 'strict') cfg.fp = r.fp;
  if (typeof r.gpc === 'boolean') cfg.gpc = r.gpc;
  return cfg;
}

function hostOfOrigin(origin: unknown): string {
  if (typeof origin !== 'string' || origin === '' || origin === 'null') return '';
  try {
    return new URL(origin).hostname;
  } catch {
    return '';
  }
}

/** Registrable domain of the top-level page this frame belongs to. */
function topSite(): string {
  let host = '';
  try {
    const ao = location.ancestorOrigins;
    if (ao !== undefined && ao !== null && ao.length > 0) host = hostOfOrigin(ao[ao.length - 1]);
    if (host === '') {
      // Top frame (or a detached about:blank that inherited an origin).
      host = location.hostname || hostOfOrigin(location.origin);
    }
  } catch {
    // ignore
  }
  if (host === '') return '';
  if (host.charCodeAt(0) === 0x5b /* [ */) host = host.slice(1, -1);
  return registrableDomain(host);
}

/**
 * Fallback when the seed files did not deliver all SEED_SETS words (broken
 * or stale registration): a random per-frame seed. Values then differ
 * between frames and loads of a site, but never link two sites.
 */
function randomSeeds(): Uint32Array {
  const out = new Uint32Array(SEED_SETS);
  try {
    crypto.getRandomValues(out);
  } catch {
    for (let i = 0; i < SEED_SETS; i++) out[i] = (Math.random() * 4294967296) >>> 0;
  }
  return out;
}

function hex8(n: number): string {
  return (n >>> 0).toString(16).padStart(8, '0');
}

// ---------------------------------------------------------------------------
// 4. Feature patches.
// ---------------------------------------------------------------------------

/** getImageData reads smaller than this stay exact (eyedroppers, 1-px hit tests). */
const MIN_2D_READ_PIXELS = 16;
/** readPixels reads smaller than this stay exact (GPU picking reads 1x1..7x7). */
const MIN_GL_READ_PIXELS = 64;
/** Up to this many changed pixels are written back one by one (exact for translucent neighbours). */
const MAX_POINT_PUTS = 256;

const GL_RGBA = 0x1908;
const GL_UNSIGNED_BYTE = 0x1401;
const GL_PACK_ALIGNMENT = 0x0d05;
const GL_PACK_ROW_LENGTH = 0x0d02;
const GL_PACK_SKIP_ROWS = 0x0d03;
const GL_PACK_SKIP_PIXELS = 0x0d04;
const GL_FRAMEBUFFER_BINDING = 0x8ca6;
const GL_READ_FRAMEBUFFER_BINDING = 0x8caa;
const GL_VENDOR = 0x1f00;
const GL_RENDERER = 0x1f01;
const GL_VERSION = 0x1f02;
const GL_SHADING_LANGUAGE_VERSION = 0x8b8c;
const UNMASKED_VENDOR_WEBGL = 0x9245;
const UNMASKED_RENDERER_WEBGL = 0x9246;

function patchGpc(st: Stealth): void {
  const nav = protoOf('Navigator');
  if (nav === undefined) return;
  const d = ObjGetDesc(nav, 'globalPrivacyControl');
  if (d !== undefined && typeof d.get === 'function') {
    st.wrapGetter(nav, 'globalPrivacyControl', (orig) => (t) => {
      RApply(orig, t, []);
      return true;
    });
    return;
  }
  // Not implemented natively: define it like a WebIDL attribute. A native
  // Navigator getter validates the receiver, so bad receivers throw
  // "Illegal invocation" exactly as a real attribute would.
  const validate = accessor(nav, 'userAgent', 'get');
  st.defineGetter(
    nav,
    'globalPrivacyControl',
    (t) => {
      if (validate !== undefined) RApply(validate, t, []);
      return true;
    },
    true,
  );
}

function patchCanvas(st: Stealth, key: Uint32Array): void {
  const C2D = protoOf('CanvasRenderingContext2D');
  const OC2D = protoOf('OffscreenCanvasRenderingContext2D');
  const HCE = protoOf('HTMLCanvasElement');
  const OCP = protoOf('OffscreenCanvas');
  const OCCtor = G.OffscreenCanvas as (new (w: number, h: number) => object) | undefined;
  const IDP = protoOf('ImageData');

  const imgData = accessor(IDP, 'data', 'get');
  const imgWidth = accessor(IDP, 'width', 'get');
  const imgHeight = accessor(IDP, 'height', 'get');
  const c2dCanvas = accessor(C2D, 'canvas', 'get');
  const oc2dCanvas = accessor(OC2D, 'canvas', 'get');
  const c2dGetImageData = method(C2D, 'getImageData');
  const c2dPutImageData = method(C2D, 'putImageData');
  const c2dDrawImage = method(C2D, 'drawImage');
  const oc2dGetImageData = method(OC2D, 'getImageData');
  const oc2dPutImageData = method(OC2D, 'putImageData');
  const oc2dDrawImage = method(OC2D, 'drawImage');
  const canvasWidth = accessor(HCE, 'width', 'get');
  const canvasHeight = accessor(HCE, 'height', 'get');
  const canvasSetWidth = accessor(HCE, 'width', 'set');
  const canvasSetHeight = accessor(HCE, 'height', 'set');
  const canvasGetContext = method(HCE, 'getContext');
  const ocWidth = accessor(OCP, 'width', 'get');
  const ocHeight = accessor(OCP, 'height', 'get');
  const ocGetContext = method(OCP, 'getContext');
  const createElement = method(protoOf('Document'), 'createElement');
  const ownerDocument = accessor(protoOf('Node'), 'ownerDocument', 'get');
  const doc0 = document;

  /** Size of the canvas behind a 2D context ([0, 0] when unknown). */
  const canvasSize = (ctx: unknown, canvasGetter: AnyFn | undefined): [number, number] => {
    if (canvasGetter === undefined) return [0, 0];
    const c = RApply(canvasGetter, ctx, []);
    if (c === null || typeof c !== 'object') return [0, 0];
    const p = ObjGetProto(c);
    if (p === HCE && canvasWidth !== undefined && canvasHeight !== undefined) {
      return [RApply(canvasWidth, c, []) as number, RApply(canvasHeight, c, []) as number];
    }
    if (p === OCP && ocWidth !== undefined && ocHeight !== undefined) {
      return [RApply(ocWidth, c, []) as number, RApply(ocHeight, c, []) as number];
    }
    return [0, 0];
  };

  /** Farble an ImageData a page asked for; x0/y0 are its canvas position. */
  const farbleImageData = (img: unknown, x0: number, y0: number, cw: number, ch: number): void => {
    if (imgData === undefined || imgWidth === undefined || imgHeight === undefined) return;
    const data = RApply(imgData, img, []) as Uint8ClampedArray;
    // Float16 ImageData (pixelFormat "rgba-float16") and anything exotic stay exact.
    if (data === null || typeof data !== 'object' || ObjGetProto(data) !== U8CProto) return;
    const w = RApply(imgWidth, img, []) as number;
    const h = RApply(imgHeight, img, []) as number;
    if (!(w * h >= MIN_2D_READ_PIXELS)) return;
    const whole = x0 === 0 && y0 === 0 && w === cw && h === ch;
    farblePixels({ data, offset: 0, width: w, height: h, rowStride: w * 4, x0, y0 }, key, {
      minAlpha: 1,
      threshold: flipThreshold(cw > 0 && ch > 0 ? cw * ch : w * h),
      minFlips: whole ? MIN_FLIPS : 0,
    });
  };

  /**
   * Farble a scratch ImageData and write the changed pixels back into the
   * scratch context. Returns false when nothing changed (the caller then
   * uses the untouched original, which keeps native output byte-exact).
   */
  const farbleInto = (ctx: unknown, img: unknown, w: number, h: number, put: AnyFn): boolean => {
    const data = RApply(imgData as AnyFn, img, []) as Uint8ClampedArray;
    if (ObjGetProto(data) !== U8CProto) return false;
    const xs = new I32(MAX_POINT_PUTS);
    const ys = new I32(MAX_POINT_PUTS);
    let n = 0;
    const changed = farblePixels(
      { data, offset: 0, width: w, height: h, rowStride: w * 4, x0: 0, y0: 0 },
      key,
      { minAlpha: 1, threshold: flipThreshold(w * h), minFlips: MIN_FLIPS },
      (x, y) => {
        if (n < MAX_POINT_PUTS) {
          xs[n] = x;
          ys[n] = y;
        }
        n++;
      },
    );
    if (changed === 0) return false;
    if (n <= MAX_POINT_PUTS) {
      // 1x1 dirty rects: neighbouring translucent pixels are never round-tripped.
      for (let i = 0; i < n; i++) RApply(put, ctx, [img, 0, 0, xs[i], ys[i], 1, 1]);
    } else {
      RApply(put, ctx, [img, 0, 0]);
    }
    return true;
  };

  const scratchOptions = (): object => {
    const o = ObjCreate(null) as Record<string, unknown>;
    o.willReadFrequently = true;
    return o;
  };

  /** Farbled copy of an HTMLCanvasElement (2D or WebGL), or null to use the original. */
  const canvasCopy = (src: unknown): object | null => {
    if (
      canvasWidth === undefined || canvasHeight === undefined || canvasSetWidth === undefined ||
      canvasSetHeight === undefined || canvasGetContext === undefined || createElement === undefined ||
      c2dDrawImage === undefined || c2dGetImageData === undefined || c2dPutImageData === undefined ||
      imgData === undefined
    ) {
      return null;
    }
    const w = RApply(canvasWidth, src, []) as number;
    const h = RApply(canvasHeight, src, []) as number;
    if (!(w > 0 && h > 0) || w * h > MAX_FARBLE_PIXELS) return null;
    let doc = ownerDocument !== undefined ? RApply(ownerDocument, src, []) : null;
    if (doc === null || doc === undefined) doc = doc0;
    const sc = RApply(createElement, doc, ['canvas']) as object;
    RApply(canvasSetWidth, sc, [w]);
    RApply(canvasSetHeight, sc, [h]);
    const ctx = RApply(canvasGetContext, sc, ['2d', scratchOptions()]);
    if (ctx === null || ctx === undefined) return null;
    RApply(c2dDrawImage, ctx, [src, 0, 0]);
    // Throws SecurityError for tainted canvases: the caller then runs the
    // original, which throws the same error natively.
    const img = RApply(c2dGetImageData, ctx, [0, 0, w, h]);
    return farbleInto(ctx, img, w, h, c2dPutImageData) ? sc : null;
  };

  const offscreenCopy = (src: unknown): object | null => {
    if (
      OCCtor === undefined || ocWidth === undefined || ocHeight === undefined || ocGetContext === undefined ||
      oc2dDrawImage === undefined || oc2dGetImageData === undefined || oc2dPutImageData === undefined ||
      imgData === undefined
    ) {
      return null;
    }
    const w = RApply(ocWidth, src, []) as number;
    const h = RApply(ocHeight, src, []) as number;
    if (!(w > 0 && h > 0) || w * h > MAX_FARBLE_PIXELS) return null;
    const sc = new OCCtor(w, h);
    const ctx = RApply(ocGetContext, sc, ['2d', scratchOptions()]);
    if (ctx === null || ctx === undefined) return null;
    RApply(oc2dDrawImage, ctx, [src, 0, 0]);
    const img = RApply(oc2dGetImageData, ctx, [0, 0, w, h]);
    return farbleInto(ctx, img, w, h, oc2dPutImageData) ? sc : null;
  };

  // getImageData: farble the fresh ImageData the page receives.
  const getImageDataImpl = (canvasGetter: AnyFn | undefined) => (orig: AnyFn) => (t: unknown, args: unknown[]): unknown => {
    const img = RApply(orig, t, args);
    try {
      // Positions only key the noise: non-numeric arguments are not coerced
      // a second time (that would be observable), they just count as 0.
      const sx = args[0], sy = args[1], sw = args[2], sh = args[3];
      let x0 = typeof sx === 'number' ? sx | 0 : 0;
      let y0 = typeof sy === 'number' ? sy | 0 : 0;
      if (typeof sw === 'number' && sw < 0) x0 += sw | 0;
      if (typeof sh === 'number' && sh < 0) y0 += sh | 0;
      const size = canvasSize(t, canvasGetter);
      farbleImageData(img, x0, y0, size[0], size[1]);
    } catch {
      // keep the native result
    }
    return img;
  };
  st.wrapMethod(C2D, 'getImageData', getImageDataImpl(c2dCanvas));
  st.wrapMethod(OC2D, 'getImageData', getImageDataImpl(oc2dCanvas));

  // toDataURL / toBlob: encode a farbled copy; the visible canvas is never modified.
  st.wrapMethod(HCE, 'toDataURL', (orig) => (t, args) => {
    let src: unknown = t;
    try {
      const c = canvasCopy(t);
      if (c !== null) src = c;
    } catch {
      src = t;
    }
    const out = RApply(orig, src, args);
    if (src !== t) {
      try {
        // Release the scratch backing store right away (toDataURL is synchronous).
        RApply(canvasSetWidth as AnyFn, src, [0]);
      } catch {
        // ignore
      }
    }
    return out;
  });
  st.wrapMethod(HCE, 'toBlob', (orig) => (t, args) => {
    let src: unknown = t;
    try {
      const c = canvasCopy(t);
      if (c !== null) src = c;
    } catch {
      src = t;
    }
    return RApply(orig, src, args);
  });
  st.wrapMethod(OCP, 'convertToBlob', (orig) => (t, args) => {
    let src: unknown = t;
    try {
      const c = offscreenCopy(t);
      if (c !== null) src = c;
    } catch {
      src = t;
    }
    return RApply(orig, src, args);
  });
}

function patchWebGL(st: Stealth, key: Uint32Array, strict: boolean): void {
  const targets: [Proto, boolean][] = [
    [protoOf('WebGLRenderingContext'), false],
    [protoOf('WebGL2RenderingContext'), true],
  ];
  for (let ti = 0; ti < targets.length; ti++) {
    const proto = targets[ti][0];
    const isGL2 = targets[ti][1];
    if (proto === undefined) continue;
    const getParameter = method(proto, 'getParameter');
    const bufferWidth = accessor(proto, 'drawingBufferWidth', 'get');
    const bufferHeight = accessor(proto, 'drawingBufferHeight', 'get');
    if (getParameter === undefined) continue;

    st.wrapMethod(proto, 'readPixels', (orig) => (t, args) => {
      const r = RApply(orig, t, args);
      try {
        farbleReadPixels(t, args, getParameter, bufferWidth, bufferHeight, isGL2, key);
      } catch {
        // keep the native result
      }
      return r;
    });

    if (strict) {
      st.wrapMethod(proto, 'getParameter', (orig) => (t, args) => {
        const r = RApply(orig, t, args);
        if (typeof r !== 'string' || args.length === 0) return r;
        const p = args[0];
        if (p === UNMASKED_VENDOR_WEBGL) return RApply(orig, t, [GL_VENDOR]);
        if (p === UNMASKED_RENDERER_WEBGL) return RApply(orig, t, [GL_RENDERER]);
        if (typeof p === 'number') return r;
        // pname was an object the browser coerced (valueOf tricks): anything
        // that is not one of the standard strings must be an unmasked one.
        try {
          const vendor = RApply(orig, t, [GL_VENDOR]);
          const renderer = RApply(orig, t, [GL_RENDERER]);
          if (r === vendor || r === renderer) return r;
          if (r === RApply(orig, t, [GL_VERSION]) || r === RApply(orig, t, [GL_SHADING_LANGUAGE_VERSION])) return r;
          return RApply(strIndexOf, r, [',']) !== -1 ? renderer : vendor;
        } catch {
          return r;
        }
      });
    }
  }
}

function farbleReadPixels(
  gl: unknown,
  args: unknown[],
  getParameter: AnyFn,
  bufferWidth: AnyFn | undefined,
  bufferHeight: AnyFn | undefined,
  isGL2: boolean,
  key: Uint32Array,
): void {
  if (args.length < 7) return;
  const x = args[0], y = args[1], w = args[2], h = args[3];
  if (typeof x !== 'number' || typeof y !== 'number' || typeof w !== 'number' || typeof h !== 'number') return;
  if (args[4] !== GL_RGBA || args[5] !== GL_UNSIGNED_BYTE) return;
  const pixels = args[6];
  // The WebGL2 pixel-pack-buffer overload passes a number: nothing to farble here.
  if (pixels === null || typeof pixels !== 'object') return;
  const pp = ObjGetProto(pixels);
  if (pp !== U8Proto && pp !== U8CProto) return;
  const wi = w | 0;
  const hi = h | 0;
  if (wi <= 0 || hi <= 0 || wi * hi < MIN_GL_READ_PIXELS) return;
  let offset = 0;
  if (args.length > 7 && args[7] !== undefined) {
    if (typeof args[7] !== 'number') return;
    offset = (args[7] as number) | 0;
  }
  // Only read-backs of the canvas itself (default framebuffer) are noised.
  // Framebuffer objects carry GPGPU data (ML inference, colour-ID picking)
  // that must stay exact; fingerprinting reads what was drawn to the canvas,
  // which toDataURL/toBlob cover as well.
  if (RApply(getParameter, gl, [isGL2 ? GL_READ_FRAMEBUFFER_BINDING : GL_FRAMEBUFFER_BINDING]) !== null) return;
  let align = RApply(getParameter, gl, [GL_PACK_ALIGNMENT]) as number;
  if (align !== 1 && align !== 2 && align !== 4 && align !== 8) align = 4;
  if (isGL2) {
    // Custom pack layouts are rare; leave them exact rather than guess.
    if (RApply(getParameter, gl, [GL_PACK_ROW_LENGTH]) || RApply(getParameter, gl, [GL_PACK_SKIP_ROWS]) ||
        RApply(getParameter, gl, [GL_PACK_SKIP_PIXELS])) {
      return;
    }
  }
  const stride = mathCeil((wi * 4) / align) * align;
  const data = pixels as Uint8Array;
  if (offset < 0 || offset + stride * (hi - 1) + wi * 4 > lengthOf(data)) return;
  const dbw = bufferWidth !== undefined ? (RApply(bufferWidth, gl, []) as number) : 0;
  const dbh = bufferHeight !== undefined ? (RApply(bufferHeight, gl, []) as number) : 0;
  const x0 = x | 0;
  const y0 = y | 0;
  const whole = x0 === 0 && y0 === 0 && wi === dbw && hi === dbh;
  farblePixels(
    { data, offset, width: wi, height: hi, rowStride: stride, x0, y0, yFlip: dbh > 0 ? dbh - 1 : -1 },
    key,
    { minAlpha: 255, threshold: flipThreshold(dbw > 0 && dbh > 0 ? dbw * dbh : wi * hi), minFlips: whole ? MIN_FLIPS : 0 },
  );
}

function patchAudio(st: Stealth, key: Uint32Array): void {
  const AN = protoOf('AnalyserNode');
  const AB = protoOf('AudioBuffer');
  const analyserKey = audioKey(key, 1000);

  const floatAfter = (orig: AnyFn) => (t: unknown, args: unknown[]): unknown => {
    const r = RApply(orig, t, args);
    try {
      const a = args[0];
      if (a !== null && typeof a === 'object' && ObjGetProto(a) === F32Proto) farbleFloats(a as Float32Array, analyserKey, 0);
    } catch {
      // keep native data
    }
    return r;
  };
  const bytesAfter = (center: number) => (orig: AnyFn) => (t: unknown, args: unknown[]): unknown => {
    const r = RApply(orig, t, args);
    try {
      const a = args[0];
      if (a !== null && typeof a === 'object' && ObjGetProto(a) === U8Proto) farbleBytes(a as Uint8Array, analyserKey, center);
    } catch {
      // keep native data
    }
    return r;
  };
  st.wrapMethod(AN, 'getFloatFrequencyData', floatAfter);
  st.wrapMethod(AN, 'getFloatTimeDomainData', floatAfter);
  st.wrapMethod(AN, 'getByteFrequencyData', bytesAfter(0));
  st.wrapMethod(AN, 'getByteTimeDomainData', bytesAfter(128));

  // AudioBuffer channel arrays are live views of the buffer: farble each one
  // exactly once, in place, so repeated reads neither compound the factor
  // nor disagree with copyFromChannel.
  const done = new WeakSetCtor<object>();
  const origGetChannelData = method(AB, 'getChannelData');
  const farbleOnce = (arr: unknown, channel: unknown): void => {
    if (arr === null || typeof arr !== 'object' || ObjGetProto(arr) !== F32Proto) return;
    if (RApply(wsHas, done, [arr])) return;
    RApply(wsAdd, done, [arr]);
    const n = lengthOf(arr as Float32Array);
    if (n === 0 || n > MAX_AUDIO_SAMPLES) return;
    farbleFloats(arr as Float32Array, audioKey(key, typeof channel === 'number' ? channel | 0 : 0), 0);
  };
  st.wrapMethod(AB, 'getChannelData', (orig) => (t, args) => {
    const arr = RApply(orig, t, args);
    try {
      farbleOnce(arr, args[0]);
    } catch {
      // keep native data
    }
    return arr;
  });
  st.wrapMethod(AB, 'copyFromChannel', (orig) => (t, args) => {
    // Farble the source channel in place first; the native copy then carries
    // the same noise getChannelData would show.
    if (origGetChannelData !== undefined && typeof args[1] === 'number') {
      try {
        farbleOnce(RApply(origGetChannelData, t, [args[1]]), args[1]);
      } catch {
        // invalid channel: the native call below reports it
      }
    }
    return RApply(orig, t, args);
  });
}

function patchNavigator(st: Stealth, key: Uint32Array, strict: boolean): void {
  const nav = protoOf('Navigator');
  if (nav === undefined) return;
  st.wrapGetter(nav, 'hardwareConcurrency', (orig) => {
    let lastReal: unknown = NaN;
    let value: unknown = 0;
    const word = keyedWord(key, PURPOSE.CORES);
    return (t) => {
      const real = RApply(orig, t, []);
      if (real !== lastReal) {
        lastReal = real;
        value = typeof real === 'number' ? farbleConcurrency(real, word, strict) : real;
      }
      return value;
    };
  });
  st.wrapGetter(nav, 'deviceMemory', (orig) => {
    let lastReal: unknown = NaN;
    let value: unknown = 0;
    const word = keyedWord(key, PURPOSE.MEMORY);
    return (t) => {
      const real = RApply(orig, t, []);
      if (real !== lastReal) {
        lastReal = real;
        value = typeof real === 'number' ? farbleDeviceMemory(real, word, strict) : real;
      }
      return value;
    };
  });
}

function patchStrict(st: Stealth, key: Uint32Array): void {
  const nav = protoOf('Navigator');
  const language = accessor(nav, 'language', 'get');
  if (nav !== undefined && language !== undefined) {
    st.wrapGetter(nav, 'languages', (orig) => {
      let lastLang: unknown;
      let frozen: unknown;
      return (t) => {
        RApply(orig, t, []); // receiver validation
        const lang = RApply(language, t, []);
        if (frozen === undefined || lang !== lastLang) {
          lastLang = lang;
          frozen = ObjFreeze(typeof lang === 'string' && lang !== '' ? [lang] : []);
        }
        return frozen;
      };
    });
  }

  st.wrapMethod(protoOf('SpeechSynthesis'), 'getVoices', (orig) => (t, args) => {
    RApply(orig, t, args);
    return [];
  });

  st.wrapMethod(protoOf('MediaDevices'), 'enumerateDevices', (orig) => (t, args) => {
    const p = RApply(orig, t, args);
    const reorder = (list: unknown): unknown => {
      try {
        if (!arrayIsArray(list)) return list;
        const copy = RApply(arraySlice, list, []) as unknown[];
        shuffleInPlace(copy, new Prng(key, PURPOSE.DEVICES));
        return copy;
      } catch {
        return list;
      }
    };
    return RApply(promiseThen, p, [reorder]);
  });

  const MDI = protoOf('MediaDeviceInfo');
  st.wrapGetter(MDI, 'label', (orig) => (t) => {
    RApply(orig, t, []);
    return '';
  });
  st.wrapMethod(MDI, 'toJSON', (orig) => (t, args) => {
    const o = RApply(orig, t, args);
    try {
      if (o !== null && typeof o === 'object') (o as Record<string, unknown>).label = '';
    } catch {
      // ignore
    }
    return o;
  });
}

// ---------------------------------------------------------------------------
// 5. Main.
// ---------------------------------------------------------------------------

function main(): void {
  if (typeof window === 'undefined' || typeof document === 'undefined') return;
  const cfg = parseCfg(rawCfg);
  if (cfg.fp === 'off' && !cfg.gpc) return;

  // Fewer words than SEED_SETS would shrink the seed space (a set-by-set
  // search becomes feasible again), so anything short falls back to random.
  const seeds = normalizeSeeds(rawSeeds, SEED_SETS) ?? randomSeeds();
  const site = topSite();
  const key = deriveSiteKey(seeds, site);

  // A second copy in the same realm (overlapping registrations) must not
  // add noise twice. The sentinel is derived from the key, so pages cannot
  // probe for it.
  const sentinel = 'b' + hex8(keyedWord(key, PURPOSE.SENTINEL)) + hex8(keyedWord(key, PURPOSE.SENTINEL + 64));
  const reply = 'r' + hex8(keyedWord(key, PURPOSE.SENTINEL + 128));
  if (realmAlreadyPatched(sentinel, reply)) return;

  const st = createStealth(ownStackNeedle(), sentinel, reply);
  if (cfg.gpc) safe(() => patchGpc(st));
  if (cfg.fp !== 'off') {
    const strict = cfg.fp === 'strict';
    safe(() => patchCanvas(st, key));
    safe(() => patchWebGL(st, key, strict));
    safe(() => patchAudio(st, key));
    safe(() => patchNavigator(st, key, strict));
    if (strict) safe(() => patchStrict(st, key));
  }
  st.installToString(findAncestorMask(window, sentinel, reply));
}

safe(main);
