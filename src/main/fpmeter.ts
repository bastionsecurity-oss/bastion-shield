// Bastion Shield — nerd mode fingerprinting meter, MAIN world (dist/main/fpmeter.js).
//
// Counts calls of fingerprinting-prone APIs per vector (FpVector) and
// reports them to the ISOLATED relay (nerd-relay.js), which forwards them
// to the service worker for the popup. It only counts: every wrapper
// increments a closure counter and calls through, so behaviour, return
// values and errors are the native ones (or privacy.js's, see below).
// Counters are flushed at most once per FLUSH_MS while calls happen, and on
// pagehide.
//
// What is counted (raw calls, not a verdict: a photo editor reads pixels too):
//   canvas     toDataURL, toBlob, convertToBlob, getImageData (2D, offscreen)
//   webgl      getParameter(UNMASKED_VENDOR/RENDERER), getSupportedExtensions,
//              getExtension('WEBGL_debug_renderer_info'),
//              getShaderPrecisionFormat, readPixels
//   audio      OfflineAudioContext.startRendering, AnalyserNode reads on an
//              OfflineAudioContext (live visualisers are not counted)
//   fonts      document.fonts.check, and measureText with a font string
//              beyond the first FONT_FREE distinct ones (font probing walks
//              hundreds of families; normal pages use a handful)
//   navigator  plugins, mimeTypes, hardwareConcurrency, deviceMemory,
//              languages, userAgentData.getHighEntropyValues
//   screen     screen.* metrics, devicePixelRatio
//   media      enumerateDevices, speechSynthesis.getVoices
//   timing     not counted: performance.now is called per animation frame by
//              ordinary pages, so a count would be noise and the wrapper a cost.
//
// Coexistence with privacy.js: the service worker lists fpmeter.js right
// after privacy.js in the same registration (registrations.ts), so in every
// frame the meter runs second and wraps privacy's proxies. Page calls are
// counted once, and privacy.js's own internal calls (it captured the natives
// before the meter existed, e.g. the scratch-canvas getImageData behind a
// farbled toDataURL) are not counted at all. Had the meter run first,
// privacy.js would have captured the meter's proxies and every farbled
// toDataURL would count twice. Both scripts chain their
// Function.prototype.toString masks, so either order keeps toString native.
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { encodeFp, FP_ORDER } from './nerd-channel.ts';
import { setupNerdMain } from './nerd-main.ts';
import type { NerdMain } from './nerd-main.ts';
import type { FpVector } from '../shared/types.ts';

const RApply = Reflect.apply;
const ObjGetDesc = Object.getOwnPropertyDescriptor;
const ObjGetProto = Object.getPrototypeOf;
const ObjCreate = Object.create;
const SetCtor = Set;
const setHas = Set.prototype.has;
const setAdd = Set.prototype.add;
const setSize = Object.getOwnPropertyDescriptor(Set.prototype, 'size')?.get as (() => number) | undefined;
const setTimeoutFn = typeof setTimeout === 'function' ? setTimeout : undefined;
const G = globalThis as unknown as Record<string, unknown>;

type AnyFn = (...args: unknown[]) => unknown;
type Proto = Record<string, unknown> | undefined;

const FLUSH_MS = 1000;
/** Distinct measureText fonts a page may use before further ones count as probing. */
export const FONT_FREE = 20;
/** Distinct fonts remembered (beyond that every new one simply counts). */
const FONT_MEMORY = 2048;
/** Per-vector cap between flushes. */
const MAX_PENDING = 1_000_000;

const UNMASKED_VENDOR_WEBGL = 0x9245;
const UNMASKED_RENDERER_WEBGL = 0x9246;

const IDX: Readonly<Record<FpVector, number>> = (() => {
  const o = ObjCreate(null) as Record<FpVector, number>;
  for (let i = 0; i < FP_ORDER.length; i++) o[FP_ORDER[i]] = i;
  return o;
})();

function protoOf(name: string): Proto {
  try {
    const c = G[name] as { prototype?: unknown } | undefined;
    const p = typeof c === 'function' ? c.prototype : undefined;
    return p !== null && typeof p === 'object' ? (p as Record<string, unknown>) : undefined;
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

function install(nm: NerdMain): void {
  const st = nm.stealth;
  const counts: number[] = [0, 0, 0, 0, 0, 0, 0, 0];
  let timer = false;

  const flush = (): void => {
    timer = false;
    let any = false;
    for (let i = 0; i < counts.length; i++) if (counts[i] !== 0) any = true;
    if (!any) return;
    const detail = encodeFp(counts);
    for (let i = 0; i < counts.length; i++) counts[i] = 0;
    nm.send(detail);
  };

  const bump = (i: number): void => {
    if (counts[i] < MAX_PENDING) counts[i]++;
    if (!timer && setTimeoutFn !== undefined) {
      timer = true;
      try {
        RApply(setTimeoutFn, G, [flush, FLUSH_MS]);
      } catch {
        timer = false;
      }
    }
  };

  /** Count every call of proto[name] under `vector`. */
  const countMethod = (proto: Proto, name: string, vector: FpVector): void => {
    const i = IDX[vector];
    st.wrapMethod(proto, name, (orig) => (t, args) => {
      bump(i);
      return RApply(orig, t, args);
    });
  };
  const countGetter = (proto: object | undefined, name: string, vector: FpVector): void => {
    const i = IDX[vector];
    st.wrapGetter(proto, name, (orig) => (t) => {
      bump(i);
      return RApply(orig, t, []);
    });
  };

  // canvas
  const HCE = protoOf('HTMLCanvasElement');
  const C2D = protoOf('CanvasRenderingContext2D');
  const OC2D = protoOf('OffscreenCanvasRenderingContext2D');
  countMethod(HCE, 'toDataURL', 'canvas');
  countMethod(HCE, 'toBlob', 'canvas');
  countMethod(protoOf('OffscreenCanvas'), 'convertToBlob', 'canvas');
  countMethod(C2D, 'getImageData', 'canvas');
  countMethod(OC2D, 'getImageData', 'canvas');

  // webgl
  const gl = IDX.webgl;
  for (const name of ['WebGLRenderingContext', 'WebGL2RenderingContext']) {
    const proto = protoOf(name);
    if (proto === undefined) continue;
    st.wrapMethod(proto, 'getParameter', (orig) => (t, args) => {
      const p = args[0];
      if (p === UNMASKED_VENDOR_WEBGL || p === UNMASKED_RENDERER_WEBGL) bump(gl);
      return RApply(orig, t, args);
    });
    st.wrapMethod(proto, 'getExtension', (orig) => (t, args) => {
      if (args[0] === 'WEBGL_debug_renderer_info') bump(gl);
      return RApply(orig, t, args);
    });
    countMethod(proto, 'getSupportedExtensions', 'webgl');
    countMethod(proto, 'getShaderPrecisionFormat', 'webgl');
    countMethod(proto, 'readPixels', 'webgl');
  }

  // audio
  const OAC = protoOf('OfflineAudioContext');
  countMethod(OAC, 'startRendering', 'audio');
  const AN = protoOf('AnalyserNode');
  const nodeContext = getter(protoOf('AudioNode'), 'context');
  if (AN !== undefined && OAC !== undefined && nodeContext !== undefined) {
    const au = IDX.audio;
    for (const name of ['getFloatFrequencyData', 'getByteFrequencyData', 'getFloatTimeDomainData', 'getByteTimeDomainData']) {
      st.wrapMethod(AN, name, (orig) => (t, args) => {
        try {
          const ctx = RApply(nodeContext, t, []);
          if (ctx !== null && typeof ctx === 'object' && ObjGetProto(ctx) === OAC) bump(au);
        } catch {
          // bad receiver: the native call below reports it
        }
        return RApply(orig, t, args);
      });
    }
  }

  // fonts
  countMethod(protoOf('FontFaceSet'), 'check', 'fonts');
  const fontGet = getter(C2D, 'font');
  if (C2D !== undefined && fontGet !== undefined && setSize !== undefined) {
    const fo = IDX.fonts;
    const seen = new SetCtor<string>();
    let last = '';
    st.wrapMethod(C2D, 'measureText', (orig) => (t, args) => {
      try {
        const f = RApply(fontGet, t, []);
        if (typeof f === 'string' && f !== last) {
          last = f;
          if (!RApply(setHas, seen, [f])) {
            const n = RApply(setSize, seen, []) as number;
            if (n < FONT_MEMORY) RApply(setAdd, seen, [f]);
            if (n >= FONT_FREE) bump(fo);
          }
        }
      } catch {
        // bad receiver: the native call below reports it
      }
      return RApply(orig, t, args);
    });
  }

  // navigator
  const NAV = protoOf('Navigator');
  for (const name of ['plugins', 'mimeTypes', 'hardwareConcurrency', 'deviceMemory', 'languages']) countGetter(NAV, name, 'navigator');
  countMethod(protoOf('NavigatorUAData'), 'getHighEntropyValues', 'navigator');

  // screen
  const SCR = protoOf('Screen');
  for (const name of ['width', 'height', 'availWidth', 'availHeight', 'availLeft', 'availTop', 'colorDepth', 'pixelDepth']) {
    countGetter(SCR, name, 'screen');
  }
  // devicePixelRatio is an own accessor of the global object in Chromium; fall back to Window.prototype.
  const dprOwner = getter(G, 'devicePixelRatio') !== undefined ? G : protoOf('Window');
  countGetter(dprOwner, 'devicePixelRatio', 'screen');

  // media
  countMethod(protoOf('MediaDevices'), 'enumerateDevices', 'media');
  countMethod(protoOf('SpeechSynthesis'), 'getVoices', 'media');

  // Report what is left when the page goes away (bfcache or unload).
  const addListener = protoOf('EventTarget')?.addEventListener;
  if (typeof addListener === 'function') {
    const opts = ObjCreate(null) as AddEventListenerOptions;
    opts.capture = true;
    RApply(addListener, G, ['pagehide', flush, opts]);
  }
}

function main(): void {
  const nm = setupNerdMain('fpmeter');
  if (nm === null) return;
  try {
    install(nm);
  } catch {
    // whatever was wrapped stays wrapped; the rest stays native
  }
  nm.finish();
}

try {
  main();
} catch {
  // never throw into the page
}
