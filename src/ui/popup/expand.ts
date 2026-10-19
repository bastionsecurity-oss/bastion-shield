// Bastion Shield — compact popup <-> expanded view, as one continuous morph.
//
// Edge and Chrome rebuild the popup window when it navigates, so a page change
// (popup.html -> panel.html) can only cut. Instead the expanded view is loaded
// into an iframe inside this popup. When it has drawn:
//   1. the document grows to 760×560; the browser grows the popup to the left
//      and down (anchored at the toolbar button), and in the same frame the
//      compact layout is shifted right by the growth, so on screen it does not
//      move at all;
//   2. paired elements fly on a spring from their compact place to their place
//      in the expanded view and cross-fade (each document animates its half);
//   3. the sidebar slides in, the remaining rows rise in.
// Collapsing runs the same steps backwards, quicker, and shrinks the window
// while the tiles are still landing.
// Reduced motion, or a panel that does not report ready, falls back to the
// plain page change.
//
// SPDX-License-Identifier: GPL-3.0-or-later

import { reducedMotion } from '../shared/dom.ts';
import { t } from '../shared/i18n.ts';
import { COLLAPSE_MS, COMPACT_SELECTORS, MORPH_PAIRS, enter, finished, isMorphMessage, leave, morphIn, morphOut, rectsOf, type MorphMessage, type MorphRects } from '../shared/morph.ts';

const PANEL_W = 760;
const PANEL_H = 560;
const READY_TIMEOUT_MS = 2500;

export interface ExpandOptions {
  /** URL of the expanded view for the current tab. */
  panelUrl: () => string;
  /** Called before expanding (write the hand-off). */
  beforeExpand: () => void;
  /** Plain page change (reduced motion, or the morph could not start). */
  fallback: () => void;
  /** The expanded view hands back its latest state when it collapses. */
  onCollapse: (state: unknown) => void;
}

function pairEl(p: (typeof MORPH_PAIRS)[number]): HTMLElement | null {
  return document.querySelector<HTMLElement>(COMPACT_SELECTORS[p]);
}

/** Compact elements without a counterpart: they fade with a small drift. */
function loners(): HTMLElement[] {
  return Array.from(document.querySelectorAll<HTMLElement>('#pp-org, #pp-report, .pp-calm:not([hidden])')).filter((el) => !el.hidden);
}

export function setupExpand(opts: ExpandOptions): { expand: () => void } {
  let frame: HTMLIFrameElement | null = null;
  let busy = false;
  const root = document.documentElement;

  const post = (msg: MorphMessage): void => frame?.contentWindow?.postMessage(msg, location.origin);

  const growth = (): number => Math.max(0, PANEL_W - document.body.offsetWidth);

  const cleanup = (): void => {
    frame?.remove();
    frame = null;
    root.classList.remove('pp-x', 'pp-x-done');
    root.style.removeProperty('--pp-shift');
    busy = false;
  };

  async function expand(): Promise<void> {
    if (busy) return;
    if (reducedMotion()) {
      opts.fallback();
      return;
    }
    busy = true;
    opts.beforeExpand();
    const shift = growth();
    const iframe = document.createElement('iframe');
    iframe.id = 'pp-panel';
    iframe.title = t('popupAllSettings');
    iframe.src = opts.panelUrl();
    frame = iframe;

    const ready = new Promise<MorphRects | null>((resolve) => {
      const timer = setTimeout(() => resolve(null), READY_TIMEOUT_MS);
      const onMsg = (ev: MessageEvent): void => {
        if (ev.source !== iframe.contentWindow || ev.origin !== location.origin || !isMorphMessage(ev.data) || ev.data.bx !== 'ready') return;
        clearTimeout(timer);
        removeEventListener('message', onMsg);
        resolve(ev.data.rects);
      };
      addEventListener('message', onMsg);
    });
    document.body.append(iframe);
    const target = await ready;
    if (!target) {
      cleanup();
      opts.fallback();
      return;
    }

    // 1. Grow the window and keep the compact layout where it is on screen.
    root.style.setProperty('--pp-shift', `${shift}px`);
    root.classList.add('pp-x');
    const from = rectsOf(COMPACT_SELECTORS); // already includes the shift (transform)

    // 2. Both halves of every pair move at once; the panel fades in on top.
    post({ bx: 'in', rects: from });
    const anims: Animation[] = [];
    for (const p of MORPH_PAIRS) {
      const el = pairEl(p);
      const to = target[p];
      if (el && to) anims.push(...morphOut(el, to));
    }
    for (const el of loners()) anims.push(leave(el, 0, 0));
    anims.push(iframe.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 200, easing: 'linear', fill: 'backwards' }));
    iframe.classList.add('pp-panel--live');

    await finished(anims);
    root.classList.add('pp-x-done');
    for (const a of anims) a.cancel();
    iframe.focus();
    busy = false;
  }

  // The expanded view asks to collapse: run the morph backwards.
  addEventListener('message', (ev: MessageEvent) => {
    if (!frame || ev.source !== frame.contentWindow || ev.origin !== location.origin || !isMorphMessage(ev.data)) return;
    const msg = ev.data;
    if (msg.bx === 'close') {
      window.close();
      return;
    }
    if (msg.bx !== 'collapse' || busy) return;
    busy = true;
    const iframe = frame;
    opts.onCollapse(msg.state);
    root.classList.remove('pp-x-done');
    const to = rectsOf(COMPACT_SELECTORS);
    post({ bx: 'out', rects: to });
    const anims: Animation[] = [];
    for (const p of MORPH_PAIRS) {
      const el = pairEl(p);
      const fromBox = msg.rects[p];
      if (el && fromBox) anims.push(...morphIn(el, fromBox, undefined, 0, COLLAPSE_MS));
      else if (el) anims.push(enter(el, 0, 0, 0, COLLAPSE_MS));
    }
    for (const el of loners()) anims.push(enter(el, 0, 0, 40, COLLAPSE_MS));
    // The expanded view gives way at once: the compact tiles beneath carry the motion.
    iframe.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 110, easing: 'linear', fill: 'forwards' });
    iframe.classList.remove('pp-panel--live');
    // 3. Shrink the window while the tiles are still settling (the spring is
    // ~95 % home by then), not after: a large, emptied window that lingers reads
    // as sluggish. Dropping the shift keeps the layout where it is on screen, and
    // the running transforms are relative to it, so nothing jumps.
    const shrink = (): void => {
      if (frame === iframe) cleanup(); // also frees the gear: a quick re-click expands again
    };
    // Follow the animation clock, not the wall clock: if the first frames are
    // late, the window still waits for the tiles.
    const lead = anims[0];
    const watch = (): void => {
      if (frame !== iframe) return;
      if (!lead || Number(lead.currentTime ?? 0) >= COLLAPSE_MS * 0.55) shrink();
      else requestAnimationFrame(watch);
    };
    requestAnimationFrame(watch);
    void finished(anims).then(() => {
      shrink();
      if (frame) return; // already expanding again
      for (const a of anims) a.cancel();
      document.getElementById('pp-expand')?.focus();
    });
    // Safety: never get stuck half-way.
    setTimeout(() => {
      if (frame === iframe) cleanup();
    }, COLLAPSE_MS + 600);
  });

  return { expand: () => void expand() };
}
