// Bastion Shield — shared-element morph between the compact popup and the
// expanded view. The expanded view (panel.html) is loaded into an iframe inside
// the compact popup, so both live in one popup window and one moment: paired
// elements (tiles, gear / collapse, CTA) fly on a spring from their place in
// one layout to their place in the other while they cross-fade (FLIP). Both
// documents animate their own half with the same timing; geometry is exchanged
// with postMessage in the iframe's coordinates (it sits at 0,0 of the popup).
//
// SPDX-FileCopyrightText: 2026 Bastion Security GmbH and contributors
// SPDX-License-Identifier: GPL-3.0-or-later

export const MORPH_PAIRS = ['protect', 'blocked', 'data', 'time', 'mode', 'toggle', 'cta'] as const;
export type MorphPair = (typeof MORPH_PAIRS)[number];

export interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}
export type MorphRects = Partial<Record<MorphPair, Box>>;

/** Elements of the compact popup (popup.html). */
export const COMPACT_SELECTORS: Record<MorphPair, string> = {
  protect: '#pp-protect',
  blocked: '#pp-count-section',
  data: '.pp-stat:nth-child(1)',
  time: '.pp-stat:nth-child(2)',
  mode: '#pp-mode-section',
  toggle: '#pp-expand',
  cta: '#pp-cta-slot',
};

/** Their counterparts in «Diese Website» of the expanded view (panel.html). */
export const PANEL_SELECTORS: Record<MorphPair, string> = {
  protect: 'body[data-view="site"] .db-head',
  blocked: 'body[data-view="site"] .site-tile:nth-child(1)',
  data: 'body[data-view="site"] .site-tile:nth-child(2)',
  time: 'body[data-view="site"] .site-tile:nth-child(3)',
  mode: 'body[data-view="site"] .db-group',
  toggle: '#db-collapse',
  cta: '.db-nav__cta',
};

/** Damped spring (response 0.42 s, damping 0.86): same curve as --ease-spring. */
export const SPRING =
  'linear(0, 0.038, 0.127, 0.241, 0.362, 0.479, 0.584, 0.677, 0.754, 0.818, 0.868, 0.908, 0.938, 0.960, 0.976, 0.987, 0.995, 1, 1.003, 1.004, 1.005, 1.005, 1.005, 1.004, 1)';
export const MORPH_MS = 480;
/** Collapsing is quicker than expanding: going back should feel immediate (HIG: dismissals are brisker). */
export const COLLAPSE_MS = 320;
export const EASE_OUT = 'cubic-bezier(0.2, 0, 0, 1)';

/** Message protocol between the popup (parent) and the embedded panel. */
export type MorphMessage =
  | { bx: 'ready'; rects: MorphRects }
  | { bx: 'in'; rects: MorphRects }
  | { bx: 'collapse'; rects: MorphRects; state: unknown }
  | { bx: 'out'; rects: MorphRects }
  | { bx: 'close' };

export function isMorphMessage(data: unknown): data is MorphMessage {
  return !!data && typeof data === 'object' && typeof (data as { bx?: unknown }).bx === 'string';
}

export function boxOf(el: Element | null): Box | undefined {
  if (!el) return undefined;
  const r = el.getBoundingClientRect();
  if (r.width === 0 || r.height === 0) return undefined;
  return { x: r.left, y: r.top, w: r.width, h: r.height };
}

export function rectsOf(selectors: Record<MorphPair, string>, root: ParentNode = document, dx = 0): MorphRects {
  const out: MorphRects = {};
  for (const p of MORPH_PAIRS) {
    const b = boxOf(root.querySelector(selectors[p]));
    if (b) out[p] = { ...b, x: b.x + dx };
  }
  return out;
}

/**
 * Transform that makes an element laid out at `at` appear at `as` (origin top
 * left). Uniform scale (the smaller axis), so text and controls never squash:
 * a tile shrinks or grows proportionally into its counterpart's place.
 */
export function flipTransform(at: Box, as: Box): string {
  const s = Math.min(as.w / at.w, as.h / at.h);
  return `translate(${as.x - at.x}px, ${as.y - at.y}px) scale(${s})`;
}

/**
 * Element that ends at its own place: comes from `from` and fades in.
 * Used for the incoming half of every pair.
 */
export function morphIn(el: HTMLElement, from: Box, at: Box | undefined = boxOf(el), fadeDelay = 90, ms = MORPH_MS): Animation[] {
  if (!at) return [];
  return [
    el.animate([{ transformOrigin: '0 0', transform: flipTransform(at, from) }, { transformOrigin: '0 0', transform: 'none' }], { duration: ms, easing: SPRING, fill: 'backwards' }),
    el.animate([{ opacity: 0 }, { opacity: 1 }], { duration: Math.min(220, ms * 0.5), delay: fadeDelay, easing: EASE_OUT, fill: 'backwards' }),
  ];
}

/** Element that leaves its place: flies to `to` and fades out. The outgoing half of a pair. */
export function morphOut(el: HTMLElement, to: Box, at: Box | undefined = boxOf(el)): Animation[] {
  if (!at) return [];
  return [
    el.animate([{ transformOrigin: '0 0', transform: 'none' }, { transformOrigin: '0 0', transform: flipTransform(at, to) }], { duration: MORPH_MS, easing: SPRING, fill: 'forwards' }),
    el.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 150, delay: 20, easing: EASE_OUT, fill: 'forwards' }),
  ];
}

/** Unpaired element appearing: rises / slides from an offset. */
export function enter(el: HTMLElement, dx: number, dy: number, delay = 0, ms = MORPH_MS): Animation {
  return el.animate([{ opacity: 0, transform: `translate(${dx}px, ${dy}px)` }, { opacity: 1, transform: 'none' }], { duration: ms, delay, easing: SPRING, fill: 'backwards' });
}

/** Unpaired element leaving. */
export function leave(el: HTMLElement, dx: number, dy: number): Animation {
  return el.animate([{ opacity: 1, transform: 'none' }, { opacity: 0, transform: `translate(${dx}px, ${dy}px)` }], { duration: 220, easing: EASE_OUT, fill: 'forwards' });
}

export function finished(anims: Animation[]): Promise<void> {
  return Promise.all(anims.map((a) => a.finished.catch(() => undefined))).then(() => undefined);
}
