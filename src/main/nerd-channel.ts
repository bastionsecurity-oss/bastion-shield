// Bastion Shield — nerd mode channel between the MAIN-world scripts
// (clipguard.js, fpmeter.js) and the ISOLATED-world relay (nerd-relay.js).
//
// Transport: a cancelable CustomEvent dispatched on the frame's window with
// a string `detail` (primitives cross the world boundary; objects would not).
// dispatchEvent is synchronous, so the relay can answer a clipboard check
// in the same call by cancelling the event (preventDefault): MAIN reads the
// answer from dispatchEvent's return value. The relay therefore runs the
// detector with the isolated world's pristine built-ins, out of reach of
// page code that tampers with RegExp or String prototypes.
//
// The event name is derived from the extension origin (MAIN reads it from
// its own stack frame, the relay from chrome.runtime.getURL), so it differs
// per extension id and is not a fixed string a page could grep for. A page
// that knows the id can still listen to or forge these events; forging only
// inflates the fingerprinting counters or shows the clipboard toast, and a
// forged check's answer is ignored. Encoding uses string concatenation
// only (no JSON), so nothing page-modifiable runs on the MAIN side.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { fnv1a32 } from '../shared/hash.ts';
import type { FpVector } from '../shared/types.ts';

/** Vectors in wire order. */
export const FP_ORDER: readonly FpVector[] = ['canvas', 'webgl', 'audio', 'fonts', 'navigator', 'screen', 'media', 'timing'];

/** Where a clipboard payload comes from (see clipguard.ts). */
export type ClipSource = 'writeText' | 'write' | 'setData' | 'exec';
const CLIP_SOURCES: ReadonlySet<string> = new Set<ClipSource>(['writeText', 'write', 'setData', 'exec']);

/** Event name for an extension origin such as "chrome-extension://<id>/". */
export function nerdEventName(origin: string): string {
  return 'bsn' + fnv1a32(origin + '|nerd-channel').toString(36) + fnv1a32('v1|' + origin).toString(36);
}

/** Secret pair a second copy of a MAIN script uses to detect that its realm is already patched. */
export function nerdSentinel(origin: string, script: string): { sentinel: string; reply: string } {
  return {
    sentinel: 's' + fnv1a32(origin + '|' + script + '|s').toString(36) + fnv1a32(script + '|' + origin).toString(36),
    reply: 'r' + fnv1a32(origin + '|' + script + '|r').toString(36),
  };
}

/** "c|<source>|<1 = native user copy>|<text>" */
export function encodeClipCheck(source: ClipSource, userCopy: boolean, text: string): string {
  return 'c|' + source + '|' + (userCopy ? '1' : '0') + '|' + text;
}

/** "f|<n0>,<n1>,..." in FP_ORDER. */
export function encodeFp(counts: ArrayLike<number>): string {
  let s = 'f|';
  for (let i = 0; i < counts.length; i++) s += (i === 0 ? '' : ',') + counts[i];
  return s;
}

export type NerdDetail =
  | { kind: 'clip'; source: ClipSource; userCopy: boolean; text: string }
  | { kind: 'fp'; counts: Partial<Record<FpVector, number>> };

/** Parse an event detail (untrusted: the page can forge events). */
export function parseNerdDetail(detail: unknown): NerdDetail | null {
  if (typeof detail !== 'string' || detail.length < 2 || detail.charCodeAt(1) !== 0x7c /* | */) return null;
  if (detail[0] === 'c') {
    const a = detail.indexOf('|', 2);
    if (a < 0) return null;
    const source = detail.slice(2, a);
    if (!CLIP_SOURCES.has(source)) return null;
    const flag = detail.slice(a + 1, a + 2);
    if ((flag !== '0' && flag !== '1') || detail.charCodeAt(a + 2) !== 0x7c) return null;
    return { kind: 'clip', source: source as ClipSource, userCopy: flag === '1', text: detail.slice(a + 3) };
  }
  if (detail[0] === 'f') {
    if (detail.length > 512) return null;
    const parts = detail.slice(2).split(',');
    if (parts.length > FP_ORDER.length) return null;
    const counts: Partial<Record<FpVector, number>> = {};
    let any = false;
    for (let i = 0; i < parts.length; i++) {
      if (!/^\d{1,9}$/.test(parts[i])) return null;
      const n = Number(parts[i]);
      if (n > 0) {
        counts[FP_ORDER[i]] = n;
        any = true;
      }
    }
    return any ? { kind: 'fp', counts } : null;
  }
  return null;
}
